#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "open3"
require "optparse"
require "uri"
require "yaml"

CONTROL_PLANE_ORIGIN = "https://api.afk.ccwu.cc"
KEYCHAIN_SERVICE = "com.raydocs.tono.staging.admin-api-token"
MAXIMUM_YAML_BYTES = 1024 * 1024
MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024

def fail!(message)
  warn(message)
  exit(1)
end

def bounded_response(response)
  body = response.body || ""
  fail!("The control plane returned an oversized response.") if body.bytesize > MAXIMUM_RESPONSE_BYTES
  body
end

def request(uri, token, method, body = nil)
  # Explicit nil proxy prevents HTTP(S)_PROXY from redirecting a
  # credential-bearing catalog upload through another process.
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.open_timeout = 10
  http.read_timeout = 30
  request = method.new(uri)
  request["Accept"] = "application/json"
  request["Authorization"] = "Bearer #{token}"
  if body
    request["Content-Type"] = "application/json"
    request.body = body
  end
  response = http.request(request)
  fail!("The control-plane catalog request failed with HTTP #{response.code}.") unless response.is_a?(Net::HTTPSuccess)
  JSON.parse(bounded_response(response))
rescue JSON::ParserError
  fail!("The control plane returned invalid JSON.")
end

mode = :dry_run
parser = OptionParser.new do |options|
  options.banner = "Usage: publish-managed-catalog.rb [--dry-run|--publish|--append] /absolute/node-a.yaml [...]"
  options.on("--dry-run", "Validate and combine sources without Keychain or network access") { mode = :dry_run }
  options.on("--publish", "Replace the full catalog after validation; the default is dry-run") { mode = :publish }
  options.on("--append", "Fetch the current catalog and append uniquely named nodes") { mode = :append }
end
begin
  parser.parse!(ARGV)
rescue OptionParser::ParseError => error
  fail!(error.message)
end

token = nil
yaml = nil
begin
fail!(parser.banner) if ARGV.empty?

proxies = []
ARGV.each do |path|
  fail!("Every catalog source must use an absolute path.") unless path.start_with?("/")
  stat = File.lstat(path)
  fail!("Catalog sources must be regular files, not symlinks.") unless stat.file? && !stat.symlink?
  fail!("Catalog sources must be owned by the current user.") unless stat.uid == Process.uid
  fail!("Catalog sources must not be group/world accessible.") unless (stat.mode & 0o077).zero?
  fail!("Each catalog source must be 1 byte–1 MiB.") unless stat.size.positive? && stat.size <= MAXIMUM_YAML_BYTES

  content = File.binread(path).force_encoding(Encoding::UTF_8)
  fail!("Catalog sources must be valid UTF-8.") unless content.valid_encoding?
  document = YAML.safe_load(
    content,
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false
  )
  nodes = document.is_a?(Hash) ? document["proxies"] : nil
  fail!("Every catalog source must contain a non-empty proxies array.") unless nodes.is_a?(Array) && !nodes.empty?
  proxies.concat(nodes)
rescue Errno::ENOENT, Errno::EACCES, Psych::Exception => error
  fail!("Could not safely parse a catalog source (#{error.class}).")
end

names = proxies.map { |node| node.is_a?(Hash) ? node["name"] : nil }
fail!("Every managed node needs a non-empty string name.") unless names.all? { |name| name.is_a?(String) && !name.empty? }
fail!("Managed node names must be unique.") unless names.uniq.length == names.length

yaml = YAML.dump({ "proxies" => proxies }).sub(/\A---\s*\n/, "")
fail!("Combined catalog exceeds 1 MiB.") if yaml.bytesize > MAXIMUM_YAML_BYTES

if mode == :dry_run
  puts("Validated #{proxies.length} uniquely named incoming nodes; no credentials or network were used.")
  exit(0)
end

token, status = Open3.capture2(
  "/usr/bin/security",
  "find-generic-password",
  "-s",
  KEYCHAIN_SERVICE,
  "-w"
)
token = token.strip
fail!("The staging admin token is unavailable in Keychain.") unless status.success? && token.bytesize >= 32

origin = URI(CONTROL_PLANE_ORIGIN)
fail!("Invalid fixed control-plane origin.") unless origin.scheme == "https" && origin.port == 443 && origin.userinfo.nil?
catalog_uri = origin + "/api/v1/admin/exit-catalog"

metadata = request(catalog_uri, token, Net::HTTP::Get)
fail!("The control plane returned invalid catalog metadata.") unless metadata.is_a?(Hash)
revision = metadata["revision"]
fail!("The control plane returned an invalid catalog revision.") unless revision.is_a?(Integer) && revision >= 0

if mode == :append
  current_yaml = metadata["yaml"]
  fail!("The control plane does not support safe catalog append; deploy the matching Worker first.") unless
    current_yaml.is_a?(String) && current_yaml.bytesize <= MAXIMUM_YAML_BYTES
  begin
    current_document = YAML.safe_load(
      current_yaml,
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false
    )
  rescue Psych::Exception
    fail!("The current managed catalog is invalid YAML; refusing to append.")
  end
  current_proxies = current_document.is_a?(Hash) ? current_document["proxies"] : nil
  fail!("The current managed catalog does not contain a proxies array.") unless current_proxies.is_a?(Array)
  current_names = current_proxies.map { |node| node.is_a?(Hash) ? node["name"] : nil }
  fail!("The current managed catalog has invalid node names.") unless
    current_names.all? { |name| name.is_a?(String) && !name.empty? } && current_names.uniq.length == current_names.length
  duplicates = current_names & names
  fail!("Append would duplicate an existing managed node name: #{duplicates.first}") unless duplicates.empty?
  proxies = current_proxies + proxies
  yaml = YAML.dump({ "proxies" => proxies }).sub(/\A---\s*\n/, "")
  fail!("Combined catalog exceeds 1 MiB.") if yaml.bytesize > MAXIMUM_YAML_BYTES
end

result = request(
  catalog_uri,
  token,
  Net::HTTP::Put,
  JSON.generate({ yaml: yaml, expectedRevision: revision })
)
new_revision = result["revision"]
digest = result["sha256"]
fail!("The control plane returned invalid replacement metadata.") unless new_revision == revision + 1 && digest.is_a?(String)

verb = mode == :append ? "Appended and published" : "Published"
puts("#{verb} #{proxies.length} managed nodes as control-plane catalog revision #{new_revision}; secrets were not printed or written.")
ensure
  metadata_yaml = metadata.is_a?(Hash) ? metadata["yaml"] : nil
  metadata_yaml&.replace("\0" * metadata_yaml.bytesize)
  token&.replace("\0" * token.bytesize)
  yaml&.replace("\0" * yaml.bytesize)
end
