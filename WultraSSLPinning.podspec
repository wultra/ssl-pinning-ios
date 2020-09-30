Pod::Spec.new do |s|
  s.name = 'WultraSSLPinning'
  s.version = '1.3.0'
  # Metadata
  s.license = { :type => 'Apache License, Version 2.0', :file => 'LICENSE' }
  s.summary = 'Dynamic SSL pinning written in Swift'
  s.homepage = 'https://github.com/wultra/ssl-pinning-ios'
  s.social_media_url = 'https://twitter.com/wultra'
  s.author = { 'Wultra s.r.o.' => 'support@wultra.com' }
  s.source = { :git => 'https://github.com/wultra/ssl-pinning-ios.git', :tag => s.version }
  # Deployment targets
  s.swift_version = '5.0'
  s.ios.deployment_target = '9.0'
  # Sources
  
  # Lib is defautl subspec
  s.default_subspec = 'Lib'
  
  # 'Lib' subspec
  s.subspec 'Lib' do |sub|
    sub.source_files = 'Source/Lib/**/*.swift'
  end
  
  # 'PowerAuthIntegration' subspec
  s.subspec 'PowerAuthIntegration' do |sub|
    sub.source_files = 'Source/Plugins/PowerAuth/**/*.swift'
    sub.dependency 'WultraSSLPinning/Lib'
    sub.dependency 'PowerAuth2', '>= 0.19.1'
  end

end
