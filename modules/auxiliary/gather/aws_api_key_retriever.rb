##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Amazon Web Services (AWS) API Key Retrieval",
      'Description'    => %q{
        Pulls AWS API access and secret keys (and token) from the metadata service.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Javier Godinez <godinezj[at]gmail.com>'
        ]))

      register_options(
      [
        Opt::RPORT(80)
      ], self.class)
      deregister_options('RHOST', 'RPORT', 'VHOST')

  end

  def run
    print_status("#{peer} - Checking access...")
  end

end

