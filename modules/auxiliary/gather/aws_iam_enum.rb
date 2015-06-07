##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'
require 'openssl'
require 'base64'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Amazon Web Services (AWS) Identity and Access Management (IAM) Enumeration",
      'Description'    => %q{
        Knowing what you can do with AWS API keys once you find them on a host or github 
        is very use ful. This modules dumps the IAM policy if the API keys have the permission
        to do so, otherwise it attempts to enumerate access by performing calls to the API.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']
    ))

    register_options(
      [
        OptString.new('RHOST', [true, "AWS IAM Endpoint",'iam.amazonaws.com']),
        OptString.new('RPORT', [true, "AWS IAM Endpint Port",'443']),
        OptString.new('ACCESS_KEY', [ true, 'AWS access key' ]),
        OptString.new('SECRET', [ true, 'AWS secret key' ]),
        OptString.new('TOKEN', [ false, 'AWS session token' ]),
        OptString.new('SSL', [true, 'We doing SSL', true]),
        OptString.new('Region', [ false, 'The default region', 'us-east-1' ])
        # OptString.new('Proxies', [ false, 'The default region', 'http:127.0.0.1:8080' ])
      ], self.class)
    
  end

  def hexdigest(value)
    digest = OpenSSL::Digest::SHA256.new
    if value.respond_to?(:read)
      chunk = nil
      chunk_size = 1024 * 1024 # 1 megabyte
      digest.update(chunk) while chunk = value.read(chunk_size)
      value.rewind
    else
      digest.update(value)
    end
    digest.hexdigest
  end

  def hmac(key, value)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, value)
  end

  def hexhmac(key, value)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, value)
  end


  def request_to_sign(headers, body_digest)
    headers_block = headers.sort_by(&:first).map do |k,v| 
      v = "#{v},#{v}" if k == 'Host'
      "#{k.downcase}:#{v}" 
    end.join("\n")
    headers_list = headers.keys.sort.map {|head| head.downcase}.join(';')
    flat_request = [ "POST", "/", '', headers_block + "\n", headers_list, body_digest].join("\n")
    [headers_list, flat_request]
  end


  def sign(headers, body_digest, now)
    date = hmac("AWS4" + datastore['SECRET'], now[0,8])
    region = hmac(date, datastore['Region'])
    service = hmac(region, 'iam')
    credentials = hmac(service, 'aws4_request')
    headers_list, flat_request = request_to_sign(headers, body_digest)
    # puts "\n\n\n\n", flat_request, "\n\n\n\n"
    doc = "AWS4-HMAC-SHA256\n#{now}\n#{now[0,8]}/#{datastore['Region']}/iam/aws4_request\n#{hexdigest(flat_request)}"

    # puts datastore['SECRET'], Base64.encode64(date), Base64.encode64(region), Base64.encode64(service), Base64.encode64(credentials), doc
    signature = hexhmac(
      credentials, 
      doc
    )

    [headers_list, signature]
  end

  def auth(headers, body_digest, now)
    headers_list, signature = sign(headers, body_digest, now)
    "AWS4-HMAC-SHA256 Credential=#{datastore['ACCESS_KEY']}/#{now[0,8]}/#{datastore['Region']}/iam/aws4_request, SignedHeaders=#{headers_list}, Signature=#{signature}"
  end

  def body(vars_post)
    pstr = ""
    vars_post.each_pair do |var,val|
      pstr << '&' if pstr.length > 0
      pstr << var
      pstr << '='
      pstr << val
    end
    pstr
  end

  def headers(body_digest, body_length)
    now = Time.now.utc.strftime("%Y%m%dT%H%M%SZ")
    headers = {
      'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
      'Accept-Encoding' => '',
      'User-Agent' => 'Metasploit #{VERSION} (jg)',
      'X-Amz-Date' => now,
      'Host' => datastore['RHOST'],
      'X-Amz-Content-Sha256' => body_digest,
      # 'Content-Length' => body_length,
      'Accept' => '*/*'
    }
    headers['X-Amz-Security-Token'] = datastore['TOKEN'] if datastore['TOKEN']
    sign_headers = ['Content-Type', 'Host', 'User-Agent', 'X-Amz-Content-Sha256', 'X-Amz-Date']
    auth_headers = headers.select{|k,v| sign_headers.include?(k)}
    headers['Authorization'] = auth(auth_headers, body_digest, now)
    headers
  end

  def run
    print_status("#{peer} - Checking access (#{datastore['Region']})...")
    
    vars_post = {
      'Action' => 'GetUser',
      'Version' => '2010-05-08'
    }
    body = body(vars_post)
    body_length = body.length
    body_digest = hexdigest(body)
    
    begin
    res = send_request_raw({
      'method'   => 'POST',
      'data' => body,
      'headers' => headers(body_digest, body_length)
    })
    rescue => e
      print_status e.message
    end

    print_status res.body
  end

end

