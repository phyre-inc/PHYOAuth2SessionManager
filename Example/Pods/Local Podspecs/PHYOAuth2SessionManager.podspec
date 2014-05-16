Pod::Spec.new do |s|
  s.name             = "PHYOAuth2SessionManager"
  s.version          = "0.1.0"
  s.summary          = "An AFHTTPSessionManager subclass for authenticating via OAuth 2.0"
  s.homepage         = "http://phyreup.com"
  s.license          = 'MIT'
  s.author           = { "Matt Ricketson" => "matt@phyreup.com" }
  s.source           = { :git => "http://EXAMPLE/NAME.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/phyreup'

  # s.platform     = :ios, '5.0'
  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.7'
  s.requires_arc = true

  s.source_files = 'Classes'
  s.resources = 'Assets/*.png'

  s.public_header_files = 'Classes/**/*.h'

  s.dependency 'AFNetworking'
end
