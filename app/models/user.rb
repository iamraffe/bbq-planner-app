class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  protected
    def configure_sign_up_params
      devise_parameter_sanitizer.for(:sign_up){ |u| u.permit(:name,  :email, :password, :password_confirmation)}
    end

    def configure_account_update_params
      devise_parameter_sanitizer.for(:account_update){ |u| u.permit(:name, :email, :password, :password_confirmation) }
    end
end
