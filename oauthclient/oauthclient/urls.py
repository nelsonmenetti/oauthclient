from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Admin, for creating new Client and Scope objects. You can also create
    # these from the command line but it's easiest from the Admin.
    url(r'^admin/', include(admin.site.urls)),
    # An access-protected API endpoint, which we'll define later.
    (r'^lms/oauth', 'oauthclient.views.redirect_to_callback'),
    
    
    
)
