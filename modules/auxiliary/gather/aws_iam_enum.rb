##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'
require 'metasploit/framework/aws/client'

class Metasploit4 < Msf::Auxiliary

  include Aws::Client

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
        OptString.new('ACCESS_KEY', [ true, 'AWS access key' ]),
        OptString.new('SECRET', [ true, 'AWS secret key' ]),
        OptString.new('TOKEN', [ false, 'AWS session token' ]),
        OptString.new('SSL', [true, 'Negotiate SSL for outgoing connections', true]),
        OptString.new('Region', [ false, 'The default region', 'us-east-1' ])
      ], self.class)
    deregister_options('VHOST', 'Proxies')
  end

  def run
    actions = %w[
      GetAccessKeyLastUsed
      GetAccountAuthorizationDetails
      GetAccountPasswordPolicy
      GetAccountSummary
      GetCredentialReport
      GetGroup
      GetGroupPolicy
      GetInstanceProfile
      GetLoginProfile
      GetOpenIDConnectProvider
      GetPolicy
      GetPolicyVersion
      GetRole
      GetRolePolicy
      GetSAMLProvider
      GetServerCertificate
      GetUser
      GetUserPolicy

      ListAccessKeys
      ListAccountAliases
      ListAttachedGroupPolicies
      ListAttachedRolePolicies
      ListAttachedUserPolicies
      ListEntitiesForPolicy 
      ListGroupPolicies
      ListGroups
      ListGroupsForUser
      ListInstanceProfiles
      ListInstanceProfilesForRole
      ListMFADevices
      ListOpenIDConnectProviders
      ListPolicies
      ListPolicyVersions 
      ListRolePolicies
      ListRoles
      ListSAMLProviders
      ListServerCertificates
      ListSigningCertificates
      ListUserPolicies
      ListUsers
      ListVirtualMFADevices
    ]

    actions.each do |action|
      doc = call_iam(action)
      print_results(doc, action)
    end


    # action = "ListUsers"
    # doc = call_iam(action)
    # print_results(doc, action)

    # action = "ListRoles"
    # doc = call_iam(action)
    # print_results(doc, action)

  end

end

