#require 'securerandom'
workers Integer(ENV['WEB_CONCURRENCY'] || 2)
threads_count = Integer(ENV['THREAD_COUNT'] || 5)
threads threads_count, threads_count

rackup      DefaultRackup
port        3001
environment ENV['RACK_ENV'] || 'production'

if ENV['RACK_ENV'] == 'production'
  localhost_key = "#{File.join('/usr/share/mpcrouter/local-certs', 'localhost-key.pem')}"
  localhost_crt = "#{File.join('/usr/share/mpcrouter/local-certs', 'localhost.pem')}"
  # To be able to use rake etc
  ssl_bind '0.0.0.0', 443, {
    key: localhost_key,
    cert: localhost_crt,
    verify_mode: 'none'
  }
end

if ENV['RACK_ENV'] == 'development'
  localhost_key = "#{File.join('local-certs', 'localhost-key.pem')}"
  localhost_crt = "#{File.join('local-certs', 'localhost.pem')}"
  # To be able to use rake etc
  ssl_bind '0.0.0.0', 3000, {
    key: localhost_key,
    cert: localhost_crt,
    verify_mode: 'none'
  }
end
