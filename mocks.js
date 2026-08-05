window.FB = { init: function(){}, login: function(){}, logout: function(){} };
window.gapi = { load: function(){} };
window.p = window.p || { current: { notif: {} } };
window.grecaptcha = {
    ready: function(cb) { cb(); },
    execute: function() { return Promise.resolve('mock_token'); },
    reset: function() {},
    render: function() { return 0; }
};
