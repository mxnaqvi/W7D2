class User < ApplicationRecord
    validates :email, :session_token, presence: true, uniqueness: true
    validates :password_digest, presence: true
    validates :password, length: {minimum: 6, allow_nil: true}
    
    before_validation :ensure_session_token
    attr_reader :password

    def self.find_by_credentials(:email, password)
        user = User.find_by(email: email)

        if user && user.is_password?(password)
            user
        else
            nil
        end
    end

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end

    def is_password?(password)
        password_obj = BCrypt::password.new(self.password_digest)
        password_obj.is_password?(password)
    end

    def reset_session_token
        self.session_token = generate_session_token
        self.save!
    end

    def ensure_session_token
        self.session_token || = generate_session_token
    end

    private

    def generate_session_token
        SecureRandom::urlsafe_base64
    end

end
