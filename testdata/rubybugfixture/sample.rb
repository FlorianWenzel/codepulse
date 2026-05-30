# TODO: sanitize inputs
require 'digest'

def handle(params)
  system("echo #{params[:name]}")
  Digest::MD5.hexdigest(params[:id])
end

def danger(code)
  eval(code)
end
