require 'devise_traceable/hooks/traceable'

module Devise
  module Models
    # Trace information about your user sign in. It tracks the following columns:

    # * resource_id
    # * sign_in_at
    # * sign_out_at

    module Traceable
      def track_login!(request, session=nil)
        "#{self.class}Tracing".constantize.create({
          :sign_in_at => self.current_sign_in_at,
          :ip => request.remote_ip,
          :user_agent => request.headers["User-Agent"],
          "#{self.class}".foreign_key.to_sym => self.id
        })
      end
      def track_logout!(request, session=nil)
        
        login = "#{self.class}Tracing".constantize.where(:sign_in_at => self.current_sign_in_at, "#{self.class}".foreign_key.to_sym => self.id)
        
        if session
          last_request_at = session['last_request_at']
          new_current = timeout_in ? [Time.now, last_request_at+timeout_in].min : Time.now
        else
          new_current = Time.now
        end
        
        if login && login.first
          login.first.update_attribute(:sign_out_at, new_current)
        else
          "#{self.class}Tracing".constantize.create({
            :sign_in_at => self.current_sign_in_at,
            :ip => request.remote_ip,
            :user_agent => request.headers["User-Agent"],
            :sign_out_at => new_current,
            "#{self.class}".foreign_key.to_sym => self.id
          })
        end
      end

    end
  end
end

