#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "ipaddr"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "securerandom"
require "shellwords"
require "tmpdir"
require "yaml"

XRAY_VERSION = "v26.3.27"
XRAY_ASSETS = {
  "x86_64" => {
    name: "Xray-linux-64.zip",
    sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
  },
  "aarch64" => {
    name: "Xray-linux-arm64-v8a.zip",
    sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
  },
}.freeze
DEFAULT_REALITY_TARGET = "www.cloudflare.com"
SSH_OPTIONS = [
  "-o", "BatchMode=yes",
  "-o", "StrictHostKeyChecking=yes",
  "-o", "ConnectTimeout=10",
].freeze

class ProvisionError < StandardError; end

def fail!(message)
  raise ProvisionError, message
end

def valid_ssh_target!(value)
  fail!("--ssh must be an SSH config alias or user@host without spaces.") unless
    value&.match?(/\A(?!-)[A-Za-z0-9_.@-]+\z/)
  value
end

def valid_node_name!(value)
  name = value.to_s.strip
  fail!("--name must contain 1–80 printable characters.") if
    name.empty? || name.length > 80 || name.match?(/[[:cntrl:]]/)
  name
end

def valid_hostname!(value, flag)
  hostname = value.to_s.strip.downcase
  fail!("#{flag} must be a bounded DNS hostname.") unless
    hostname.bytesize <= 253 &&
    hostname.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/) &&
    hostname.include?(".")
  hostname
end

def valid_server!(value)
  server = value.to_s.strip.downcase
  begin
    address = IPAddr.new(server)
    fail!("The managed server endpoint must be an IPv4 address or DNS hostname.") unless address.ipv4?
    return server
  rescue IPAddr::InvalidAddressError
    valid_hostname!(server, "--server")
  end
end

def fixed_remote_command(mode, arguments)
  invocation = Shellwords.join(["/bin/bash", "-s", "--", mode, *arguments.map(&:to_s)])
  "if [ \"$(id -u)\" -eq 0 ]; then exec #{invocation}; " \
    "else exec sudo -n #{invocation}; fi"
end

def run_remote(ssh_target, remote_script, mode, arguments)
  command = ["/usr/bin/ssh", *SSH_OPTIONS, "--", ssh_target, fixed_remote_command(mode, arguments)]
  stdout, stderr, status = Open3.capture3(*command, stdin_data: remote_script)
  unless status.success?
    detail = stderr.lines.last(8).join.strip
    fail!(detail.empty? ? "SSH #{mode} operation failed." : detail)
  end
  json_line = stdout.lines.reverse.find { |line| line.lstrip.start_with?("{") }
  fail!("The VPS returned no structured #{mode} result.") unless json_line
  JSON.parse(json_line)
rescue JSON::ParserError
  fail!("The VPS returned an invalid structured #{mode} result.")
ensure
  stdout&.replace("\0" * stdout.bytesize)
end

def resolved_ssh_hostname(ssh_target)
  stdout, stderr, status = Open3.capture3("/usr/bin/ssh", "-G", "--", ssh_target)
  fail!(stderr.strip.empty? ? "Could not resolve the SSH target configuration." : stderr.strip) unless status.success?
  hostname = stdout.each_line.filter_map do |line|
    key, value = line.split(nil, 2)
    value&.strip if key == "hostname"
  end.first
  valid_server!(hostname)
end

def private_output_path!(path)
  raw = path.to_s
  fail!("The node catalog output must be an absolute path.") unless raw.start_with?("/")
  expanded = File.expand_path(raw)
  if File.exist?(expanded) || File.symlink?(expanded)
    fail!("Refusing to overwrite the existing node catalog source: #{expanded}")
  end
  parent = File.dirname(expanded)
  ancestor = parent
  loop do
    fail!("The catalog path must not traverse a symlink.") if File.symlink?(ancestor)
    break if ancestor == "/"
    ancestor = File.dirname(ancestor)
  end
  if File.exist?(parent)
    stat = File.lstat(parent)
    fail!("The catalog directory must be a private directory, not a symlink.") unless stat.directory? && !stat.symlink?
    fail!("The catalog directory must be owned by the current user.") unless stat.uid == Process.uid
    fail!("The catalog directory must not be group/world accessible (chmod 700).") unless (stat.mode & 0o077).zero?
  end
  expanded
end

def write_private_yaml(path, document)
  parent = File.dirname(path)
  FileUtils.mkdir_p(parent, mode: 0o700)
  File.chmod(0o700, parent)
  temporary = "#{path}.new-#{SecureRandom.hex(8)}"
  File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
    file.write(YAML.dump(document).sub(/\A---\s*\n/, ""))
    file.flush
    file.fsync
  end
  File.rename(temporary, path)
ensure
  File.delete(temporary) if defined?(temporary) && temporary && File.exist?(temporary)
end

def verified_xray_binary(asset, temporary_directory)
  archive = File.join(temporary_directory, asset.fetch(:name))
  url = "https://github.com/XTLS/Xray-core/releases/download/#{XRAY_VERSION}/#{asset.fetch(:name)}"
  downloaded = system(
    "/usr/bin/curl",
    "--fail", "--location", "--silent", "--show-error",
    "--proto", "=https", "--tlsv1.2",
    "--output", archive,
    url,
  )
  fail!("Could not download the pinned official Xray release.") unless downloaded
  actual = Digest::SHA256.file(archive).hexdigest
  fail!("The pinned Xray archive failed SHA-256 verification.") unless actual == asset.fetch(:sha256)

  extracted = File.join(temporary_directory, "xray")
  File.open(extracted, File::WRONLY | File::CREAT | File::EXCL, 0o700) do |destination|
    Open3.popen3("/usr/bin/unzip", "-p", archive, "xray") do |stdin, stdout, stderr, wait|
      stdin.close
      IO.copy_stream(stdout, destination)
      detail = stderr.read
      fail!(detail.empty? ? "Could not extract the verified Xray binary." : detail.strip) unless wait.value.success?
    end
  end
  fail!("The verified Xray archive contained an empty binary.") unless File.size(extracted).positive?
  File.chmod(0o700, extracted)
  extracted
end

def upload_artifact(ssh_target, local_path, remote_path)
  success = system(
    "/usr/bin/scp", "-q", *SSH_OPTIONS,
    "--", local_path, "#{ssh_target}:#{remote_path}",
  )
  fail!("Could not upload the verified Xray binary over SSH.") unless success
end

def remove_uploaded_artifact(ssh_target, remote_path)
  system(
    "/usr/bin/ssh", *SSH_OPTIONS, "--", ssh_target,
    "/bin/rm -f -- #{Shellwords.escape(remote_path)}",
    out: File::NULL,
    err: File::NULL,
  )
end

def verify_installation(repo_root, output_path, node_name, expected_ipv4)
  checks = [
    [File.join(repo_root, "tooling/scripts/test-multi-exit-policy.sh"), output_path],
    [
      File.join(repo_root, "tooling/scripts/test-isolated-data-plane.sh"),
      output_path,
      node_name,
      *([expected_ipv4].compact),
    ],
    [RbConfig.ruby, File.join(repo_root, "tooling/scripts/publish-managed-catalog.rb"), "--dry-run", output_path],
  ]
  checks.each do |command|
    fail!("Post-install verification failed: #{File.basename(command.first)}") unless system(*command)
  end
end

options = {
  port: 443,
  target: DEFAULT_REALITY_TARGET,
  apply: false,
}
parser = OptionParser.new do |flags|
  flags.banner = <<~USAGE
    Usage: provision-reality-node.rb --ssh ALIAS --name NAME [options]

    Runs a read-only VPS preflight by default. --apply installs only after the
    plan succeeds, then performs an isolated authenticated Reality data-plane test.
  USAGE
  flags.on("--ssh ALIAS", "SSH config alias or user@host (known host key required)") { |value| options[:ssh] = value }
  flags.on("--name NAME", "Unique managed node display name") { |value| options[:name] = value }
  flags.on("--server HOST", "Public IPv4/DNS endpoint; defaults to ssh -G hostname") { |value| options[:server] = value }
  flags.on("--expected-exit-ipv4 IP", "Require the final proxied egress to equal this IPv4") { |value| options[:expected_exit_ipv4] = value }
  flags.on("--servername HOST", "Reality TLS target/servername (default: #{DEFAULT_REALITY_TARGET})") { |value| options[:target] = value }
  flags.on("--port PORT", Integer, "Reality TCP port (default: 443)") { |value| options[:port] = value }
  flags.on("--output PATH", "Private one-node YAML path (default: Tono Operations catalog.d)") { |value| options[:output] = value }
  flags.on("--apply", "Install, verify, and retain the node; publication remains a separate approval") { options[:apply] = true }
end

begin
  parser.parse!(ARGV)
  fail!(parser.banner) unless ARGV.empty?
  ssh_target = valid_ssh_target!(options[:ssh])
  node_name = valid_node_name!(options[:name])
  fail!("--port must be between 1 and 65535.") unless (1..65_535).cover?(options[:port])
  target = valid_hostname!(options[:target], "--servername")
  server = options[:server] ? valid_server!(options[:server]) : resolved_ssh_hostname(ssh_target)
  expected_exit_ipv4 = if options[:expected_exit_ipv4]
    value = valid_server!(options[:expected_exit_ipv4])
    begin
      address = IPAddr.new(value)
      fail!("--expected-exit-ipv4 must be an IPv4 address, not a hostname.") unless address.ipv4?
      address.to_s
    rescue IPAddr::InvalidAddressError
      fail!("--expected-exit-ipv4 must be an IPv4 address, not a hostname.")
    end
  end
  slug = node_name.downcase.gsub(/[^a-z0-9]+/, "-").gsub(/\A-|-\z/, "")
  slug = "node-#{SecureRandom.hex(4)}" if slug.empty?
  default_output = File.join(
    Dir.home,
    "Library/Application Support/Tono/Operations/catalog.d",
    "#{slug}.yaml",
  )
  output_path = private_output_path!(options[:output] || default_output)
  repo_root = File.expand_path("../..", __dir__)
  remote_script_path = File.join(repo_root, "tooling/scripts/remote/manage-tono-reality-node.sh")
  remote_script = File.binread(remote_script_path)

  preflight = run_remote(ssh_target, remote_script, "preflight", [options[:port], target])
  fail!("The selected TCP port is already in use; no changes were made.") if preflight["portInUse"]
  fail!("This VPS already has a Tono Xray installation; use a reviewed rotation workflow.") if preflight["existingTono"]
  fail!("The selected Reality target failed TLS 1.3 verification from the VPS.") unless preflight["targetTLS13"]
  asset = XRAY_ASSETS[preflight["arch"]]
  fail!("The VPS architecture is not supported by the pinned release.") unless asset

  puts("Read-only preflight passed for #{ssh_target}: #{preflight.fetch("os")} #{preflight.fetch("arch")}, TCP #{options[:port]} free.")
  puts("Transport endpoint: #{server}:#{options[:port]}; Reality target: #{target}:443; expected final egress: #{expected_exit_ipv4 || "observe only"}.")
  puts("Plan: install pinned Xray #{XRAY_VERSION}, create an unprivileged Reality service, then test authenticated DNS/HTTPS/egress through #{node_name}.")
  puts("Firewall note: UFW is active; this tool will not alter firewall rules without separate approval.") if preflight["ufwActive"]
  unless options[:apply]
    puts("Dry run complete. Re-run with --apply after reviewing the host, target, endpoint, and firewall/provider rules.")
    exit(0)
  end

  deployment = nil
  deployment_id = "#{Time.now.utc.strftime("%Y%m%dT%H%M%SZ")}-#{SecureRandom.hex(4)}"
  apply_started = false
  output_written = false
  remote_artifact = "/tmp/tono-xray-artifact-#{SecureRandom.hex(12)}"
  begin
    Dir.mktmpdir("tono-xray-") do |temporary_directory|
      File.chmod(0o700, temporary_directory)
      binary = verified_xray_binary(asset, temporary_directory)
      binary_sha256 = Digest::SHA256.file(binary).hexdigest
      upload_artifact(ssh_target, binary, remote_artifact)
      apply_started = true
      deployment = run_remote(
        ssh_target,
        remote_script,
        "apply",
        [deployment_id, XRAY_VERSION, remote_artifact, binary_sha256, options[:port], target],
      )
    ensure
      remove_uploaded_artifact(ssh_target, remote_artifact)
    end

    fail!("The VPS returned an invalid deployment identifier.") unless
      deployment["deploymentId"].to_s.match?(/\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\z/)
    fail!("The VPS returned an invalid VLESS UUID.") unless
      deployment["uuid"].to_s.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/)
    fail!("The VPS returned an invalid Reality public key.") unless
      deployment["publicKey"].to_s.match?(/\A[A-Za-z0-9_-]{43}\z/)
    fail!("The VPS returned an invalid Reality short ID.") unless
      deployment["shortId"].to_s.match?(/\A[0-9a-f]{16}\z/)

    document = {
      "proxies" => [{
        "name" => node_name,
        "type" => "vless",
        "server" => server,
        "port" => options[:port],
        "uuid" => deployment.fetch("uuid"),
        "network" => "tcp",
        "tls" => true,
        "udp" => true,
        "servername" => target,
        "client-fingerprint" => "chrome",
        "flow" => "xtls-rprx-vision",
        "reality-opts" => {
          "public-key" => deployment.fetch("publicKey"),
          "short-id" => deployment.fetch("shortId"),
        },
      }],
    }
    write_private_yaml(output_path, document)
    output_written = true
    verify_installation(repo_root, output_path, node_name, expected_exit_ipv4)
    puts("Node installation and isolated authenticated data-plane verification passed.")
    puts("Private catalog source saved with mode 0600 at #{output_path}.")
    puts("The managed catalog was not published; publication requires a separate explicit approval.")
  rescue StandardError, Interrupt => error
    if apply_started
      begin
        result = run_remote(
          ssh_target,
          remote_script,
          "rollback",
          [deployment_id],
        )
        fail!("The VPS did not confirm rollback.") unless result["rolledBack"] == true
        File.delete(output_path) if output_written && File.exist?(output_path)
        warn("Verification failed; the new VPS service was rolled back and unpublished.")
      rescue StandardError => rollback_error
        warn("URGENT: automatic VPS rollback failed: #{rollback_error.message}")
        if output_written
          warn("The private catalog source was retained for recovery and was not published.")
        else
          warn("The remote deployment may need manual recovery; no catalog was published.")
        end
      end
    end
    raise error
  ensure
    deployment&.each_value do |value|
      value.replace("\0" * value.bytesize) if value.is_a?(String)
    end
  end
rescue ProvisionError, OptionParser::ParseError => error
  warn(error.message)
  exit(1)
end
