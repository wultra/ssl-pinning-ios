Pod::Spec.new do |s|
  s.name = 'WultraSSLPinning'
  s.version = '1.6.0'
  # Metadata
  s.license = { :type => 'Apache License, Version 2.0', :file => 'LICENSE' }
  s.summary = 'Dynamic SSL pinning written in Swift'
  s.homepage = 'https://github.com/wultra/ssl-pinning-ios'
  s.social_media_url = 'https://twitter.com/wultra'
  s.author = { 'Wultra s.r.o.' => 'support@wultra.com' }
  s.source = { :git => 'https://github.com/wultra/ssl-pinning-ios.git', :tag => s.version }
  # Deployment targets
  s.swift_version = '5.0'
  s.ios.deployment_target = '12.0'
  s.tvos.deployment_target = '12.0'
  # Sources
  
  # Lib is defautl subspec
  s.default_subspec = 'Lib'
  
  # 'Lib' subspec
  s.subspec 'Lib' do |sub|
    sub.source_files = 'Sources/WultraSSLPinning/Lib/**/*.swift'
  end
  
  # 'PowerAuthIntegration' subspec
  s.subspec 'PowerAuthIntegration' do |sub|
    sub.source_files = 'Sources/WultraSSLPinning/Plugins/PowerAuth/**/*.swift'
    sub.dependency 'WultraSSLPinning/Lib'
    sub.dependency 'PowerAuth2', '~> 1.8.0'
    sub.dependency 'PowerAuthCore', '~> 1.8.0'
  end

end
