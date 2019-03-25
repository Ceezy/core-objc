Pod::Spec.new do |s|
    s.name             = "DIMCore"
    s.version          = "0.0.1"
    s.summary          = "The core module for DIM."
    s.homepage         = "https://github.com/Ceezy/core-objc"
    s.license          = { :type => 'MIT', :file => 'LICENSE' }
    s.author           = { "Ceezy Chen" => "ceezychen@gmail.com" }
    s.source           = { :git => "https://github.com/Ceezy/core-objc.git", :tag => s.version }
#    s.social_media_url = ''

    s.platform     = :ios, '11.0'

    s.public_header_files = 'Classes/*.h'
    s.source_files = 'Classes/*.{h,m}'
    
    s.dependency 'DaoKeDao'
    s.dependency 'MingKeMing'

    s.subspec 'macros' do |ss|
        ss.source_files = 'Classes/macros/*.{h,m}'
        ss.public_header_files = 'Classes/macros/*.h'
    end

    s.subspec 'extends' do |ss|
        ss.source_files = 'Classes/extends/*.{h,m}'
        ss.public_header_files = 'Classes/extends/*.h'
    end

    s.subspec 'history' do |ss|
        ss.source_files = 'Classes/history/*.{h,m}'
        ss.public_header_files = 'Classes/history/*.h'
	ss.dependency 'DIMCore/extends'
	ss.dependency 'DIMCore/macros'
	ss.dependency 'DIMCore/manage'
    end

    s.subspec 'network' do |ss|
        ss.source_files = 'Classes/network/*.{h,m}', 'Classes/network/CA/*.{h,m}'
        ss.public_header_files = 'Classes/network/*.h', 'Classes/network/CA/*.h'
	ss.dependency 'DIMCore/macros'
	ss.dependency 'DIMCore/manage'
    end

    s.subspec 'commands' do |ss|
        ss.source_files = 'Classes/commands/*.{h,m}'
        ss.public_header_files = 'Classes/commands/*.h'
	ss.dependency 'DIMCore/manage'
    end

    s.subspec 'manage' do |ss|
        ss.source_files = 'Classes/manage/*.{h,m}'
        ss.public_header_files = 'Classes/manage/*.h'
	ss.dependency 'DIMCore/macros'
	ss.dependency 'DIMCore/extends'
    end
end
