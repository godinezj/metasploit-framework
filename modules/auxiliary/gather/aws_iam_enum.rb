##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary

  include Metasploit::Framework::Aws::Client

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
        OptString.new('RPORT', [true, "AWS IAM Endpint Port", '443']),
        OptString.new('AccessKeyId', [ true, 'AWS access key' ]),
        OptString.new('SecretAccessKey', [ true, 'AWS secret key' ]),
        OptString.new('Token', [ false, 'AWS session token' ]),
        OptString.new('SSL', [true, 'Negotiate SSL for outgoing connections', true]),
        OptString.new('Region', [ false, 'The default region', 'us-east-1' ])
      ], self.class)
    deregister_options('VHOST')
  end

  def run
    # setup creds for making IAM API calls
    creds = {
      'AccessKeyId' => datastore['AccessKeyId'],
      'SecretAccessKey' => datastore['SecretAccessKey']
    }
    creds['Token'] = datastore['Token'] unless datastore['Token'].blank?

    # toxic actions to enumerate
    actions = %w(
      CreateUser
      CreateGroup
      CreateRole
      PutRolePolicy
      PutGroupPolicy
      PutUserPolicy
      AttachGroupPolicy
      AttachRolePolicy
      AttachUserPolicy
      AddUserToGroup
      CreateAccessKey
    )

    actions.each do |action|
      doc = call_iam(creds, 'Action' => action)
      print_results(doc, action)
      break
    end
  end
end

