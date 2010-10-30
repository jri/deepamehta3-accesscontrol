function dm3_accesscontrol() {

    var DEFAULT_USER = "admin"
    var DEFAULT_PASSWORD = ""
    var ENCRYPTED_PASSWORD_PREFIX = "-SHA256-"  // don't change this

    dm3c.css_stylesheet("/de.deepamehta.3-accesscontrol/style/dm3-accesscontrol.css")
    dm3c.javascript_source("/de.deepamehta.3-accesscontrol/script/vendor/sha256.js")

    var logged_in_user      // a topic of type "de/deepamehta/core/topictype/user"

    // ------------------------------------------------------------------------------------------------------ Public API



    // *******************************
    // *** Overriding Plugin Hooks ***
    // *******************************



    this.init = function() {

        // create_default_user()
        create_login_dialog()

        function create_default_user() {

            var users = get_all_accounts()
            if (!users.length) {
                create_user(DEFAULT_USER, encrypt_password(DEFAULT_PASSWORD))
            }

            function get_all_accounts() {
                return dm3c.restc.get_topics("de/deepamehta/core/topictype/user")
            }
        }

        function create_login_dialog() {
            var login_dialog = $("<div>").attr("id", "login-dialog")
            var login_message = $("<div>").attr("id", "login-message").html("&nbsp;")
            login_dialog.append($("<div>").addClass("field-name").text("Username"))
            login_dialog.append($("<input>").attr({id: "login-username"}))
            login_dialog.append($("<div>").addClass("field-name").text("Password"))
            login_dialog.append($("<input>").attr({id: "login-password", type: "password"}))
            // Note: purpose of the login message container is maintaining the space
            // when the login message is faded out (display=none)
            login_dialog.append($("<div>").attr("id", "login-message-container").append(login_message))
            $("body").append(login_dialog)
            $("#login-message-container").height($("#login-message").height())
            $("#login-dialog").dialog({
                title: "Login", buttons: {"OK": try_login}, modal: true,
                closeOnEscape: false, draggable: false, resizable: false,
                open: function() {
                    $(".ui-dialog-titlebar-close").hide()
                }
            })
        }

        function try_login() {
            var username = $("#login-username").val()
            var password = $("#login-password").val()
            var logged_in_user = lookup_user(username, password)
            if (logged_in_user) {
                show_message("Login OK", "login-ok", function() {
                    $("#login-dialog").parent().fadeOut(400, function() {
                        $("#login-dialog").dialog("destroy")
                    })
                    // restore close box of the other dialogs
                    $(".ui-dialog-titlebar-close").show()
                })
                //
                dm3c.set_cookie("username", username)
            } else {
                show_message("Login failed", "login-failed")
            }
        }

        function show_message(message, css_class, fn) {
            $("#login-message").fadeOut(200, function() {
                $(this).text(message).removeClass().addClass(css_class).fadeIn(1000, fn)
            })
        }
    }

    /* this.pre_create = function(doc) {
        // Note: topics and relations might get created programatically,
        // e.g. by other plugins, before the user has logged in.
        if (!logged_in_user) {
            return
        }
        //
        doc.created_by = get_username()
    } */

    /* this.pre_update = function(doc) {
        // encrypt password of new accounts
        if (doc.type == "Topic" && doc.topic_type == "Account") {
            // we recognize a new account (or changed password) if password doesn't begin with ENCRYPTED_PASSWORD_PREFIX
            var password_field = get_field(doc, "Password")
            var password = password_field.content
            if (password.substring(0, ENCRYPTED_PASSWORD_PREFIX.length) != ENCRYPTED_PASSWORD_PREFIX) {
                password_field.content = encrypt_password(password)
            }
        }
        // Note: topics and relations might get created programatically,
        // e.g. by other plugins, before the user has logged in.
        if (!logged_in_user) {
            return
        }
        //
        doc.modified_by = get_username()
    } */

    // ----------------------------------------------------------------------------------------------- Private Functions

    function create_user(username, password) {
        var properties = {
            "de/deepamehta/core/property/username": username,
            "de/deepamehta/core/property/password": password
        }
        return dm3c.create_topic("de/deepamehta/core/topictype/user", properties)
    }

    function lookup_user(username, password) {
        var user = dm3c.restc.get_topic_by_property("de/deepamehta/core/property/username", username)
        if (!user) {
            return
        }
        if (user.properties["de/deepamehta/core/property/password"] == encrypt_password(password)) {
            return user
        }
    }

    function get_username() {
        return dm3c.get_value(logged_in_user, "de/deepamehta/core/property/username")
    }

    function encrypt_password(password) {
        return ENCRYPTED_PASSWORD_PREFIX + SHA256(password)
    }
}
