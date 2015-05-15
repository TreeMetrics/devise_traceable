# After each sign in, sign out.
# This is only triggered when the user is explicitly set (with set_user)
# and on authentication. Retrieving the user from session (:fetch) does
# not trigger it.

Warden::Manager.after_authentication do |record, warden, opts|
  if record.respond_to?(:track_login!)
    # warden.session(opts[:scope])
    record.track_login!(warden.request)
  end
end
Warden::Manager.before_logout do |record, warden, opts|
  if record.respond_to?(:track_logout!)
    record.track_logout!(warden.request)
  end
end

