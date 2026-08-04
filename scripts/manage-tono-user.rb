#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "open3"
require "optparse"
require "uri"

CONTROL_PLANE_ORIGIN = "https://api.afk.ccwu.cc"
KEYCHAIN_SERVICE = "com.raydocs.tono.staging.admin-api-token"
MAXIMUM_RESPONSE_BYTES = 256 * 1024

def fail!(message)
  warn(message)
  exit(1)
end

def canonical_email(value)
  address = value.to_s.strip.downcase
  fail!("A valid exact email address is required.") unless address.match?(/\A[^\s@]+@[^\s@]+\.[^\s@]+\z/) && address.bytesize <= 200
  address
end

def keychain_token
  token, status = Open3.capture2(
    "/usr/bin/security",
    "find-generic-password",
    "-s",
    KEYCHAIN_SERVICE,
    "-w"
  )
  token = token.strip
  fail!("The Tono admin token is unavailable in Keychain.") unless status.success? && token.bytesize >= 32
  token
end

def request(origin, token, method, path, payload = nil)
  uri = origin + path
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.open_timeout = 10
  http.read_timeout = 30
  call = method.new(uri)
  call["Accept"] = "application/json"
  call["Authorization"] = "Bearer #{token}"
  if payload
    call["Content-Type"] = "application/json"
    call.body = JSON.generate(payload)
  end
  response = http.request(call)
  body = response.body || ""
  fail!("The control plane returned an oversized response.") if body.bytesize > MAXIMUM_RESPONSE_BYTES
  unless response.is_a?(Net::HTTPSuccess)
    code = begin
      JSON.parse(body).dig("error", "code")
    rescue JSON::ParserError
      nil
    end
    fail!("The control-plane request failed with HTTP #{response.code}#{code ? " (#{code})" : ""}.")
  end
  body.empty? ? nil : JSON.parse(body)
rescue JSON::ParserError
  fail!("The control plane returned invalid JSON.")
end

options = { apply: false }
parser = OptionParser.new do |flags|
  flags.banner = <<~USAGE
    Usage:
      manage-tono-user.rb allow EMAIL [--apply]
      manage-tono-user.rb disallow EMAIL [--apply]
      manage-tono-user.rb show EMAIL
      manage-tono-user.rb set EMAIL [--status active|disabled] [--device-limit 1..25] [--quota-bytes N|unlimited] [--apply]
  USAGE
  flags.on("--apply", "Perform the requested mutation; otherwise mutations are dry-run") { options[:apply] = true }
  flags.on("--status STATUS", "Set active or disabled") { |value| options[:status] = value }
  flags.on("--device-limit COUNT", Integer, "Set the per-user device limit") { |value| options[:device_limit] = value }
  flags.on("--quota-bytes VALUE", "Set bytes, or unlimited") do |value|
    options[:quota_present] = true
    options[:quota_bytes] = value == "unlimited" ? nil : Integer(value, 10)
  rescue ArgumentError
    fail!("--quota-bytes must be a non-negative integer or unlimited.")
  end
end
begin
  parser.parse!(ARGV)
rescue OptionParser::ParseError => error
  fail!(error.message)
end

command = ARGV.shift
fail!(parser.banner) unless %w[allow disallow show set].include?(command)
address = canonical_email(ARGV.shift)
fail!(parser.banner) unless ARGV.empty?

if options[:status] && !%w[active disabled].include?(options[:status])
  fail!("--status must be active or disabled.")
end
if options.key?(:device_limit) && !(1..25).cover?(options[:device_limit])
  fail!("--device-limit must be between 1 and 25.")
end
if options[:quota_present] && !options[:quota_bytes].nil? && options[:quota_bytes].negative?
  fail!("--quota-bytes must be non-negative or unlimited.")
end

mutation = %w[allow disallow set].include?(command)
unless !mutation || options[:apply]
  puts("Dry run: #{command} #{address}. Re-run with --apply after reviewing the operation.")
  exit(0)
end

origin = URI(CONTROL_PLANE_ORIGIN)
fail!("Invalid fixed control-plane origin.") unless origin.scheme == "https" && origin.port == 443 && origin.userinfo.nil?
token = nil
begin
  token = keychain_token
  case command
  when "allow"
    result = request(origin, token, Net::HTTP::Post, "/api/v1/admin/signup-allowlist", { email: address })
    puts(result["created"] ? "Authorized #{address} for verified signup." : "#{address} was already authorized for verified signup.")
  when "disallow"
    request(origin, token, Net::HTTP::Delete, "/api/v1/admin/signup-allowlist", { email: address })
    puts("Removed signup authorization for #{address}; any existing account remains unchanged.")
  when "show", "set"
    users = request(origin, token, Net::HTTP::Get, "/api/v1/admin/users").fetch("users")
    user = users.find { |candidate| candidate["email"].to_s.downcase == address }
    fail!("No Tono account exists for #{address}; authorize it and have the user complete email OTP first.") unless user

    if command == "show"
      fields = %w[id email status suspended plan expiresAt quotaBytes usageBytes deviceLimit createdAt]
      puts(JSON.pretty_generate(user.select { |key, _value| fields.include?(key) }))
    else
      payload = {}
      payload[:status] = options[:status] if options[:status]
      payload[:deviceLimit] = options[:device_limit] if options.key?(:device_limit)
      payload[:quotaBytes] = options[:quota_bytes] if options[:quota_present]
      fail!("The set command needs at least one entitlement option.") if payload.empty?
      request(origin, token, Net::HTTP::Patch, "/api/v1/admin/users/#{user.fetch("id")}", payload)
      puts("Updated bounded entitlements for #{address}.")
    end
  end
ensure
  token&.replace("\0" * token.bytesize)
end
