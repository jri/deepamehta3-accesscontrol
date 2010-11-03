function dm3_accesscontrol() {

    var DEFAULT_USER = "admin"
    var DEFAULT_PASSWORD = ""
    var ENCRYPTED_PASSWORD_PREFIX = "-SHA256-"  // don't change this

    dm3c.css_stylesheet("/de.deepamehta.3-accesscontrol/style/dm3-accesscontrol.css")
    dm3c.javascript_source("/de.deepamehta.3-accesscontrol/script/vendor/sha256.js")

    // ------------------------------------------------------------------------------------------------------ Public API



    // *******************************
    // *** Overriding Plugin Hooks ***
    // *******************************



    this.init = function() {

        if (get_username()) {
            dm3c.add_to_special_menu({value: "loginout-item", label: "Logout \"" + get_username() + "\""})
        } else {
            dm3c.add_to_special_menu({value: "loginout-item", label: "Login..."})
        }

        create_login_dialog()

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
                title: "Login", buttons: {"OK": do_login},
                modal: true, autoOpen: false, closeOnEscape: false, draggable: false, resizable: false,
                open: function() {
                    $(".ui-dialog-titlebar-close").hide()
                }
            })
        }

        function do_login() {
            var username = $("#login-username").val()
            var password = $("#login-password").val()
            var logged_in_user = lookup_user(username, password)
            if (logged_in_user) {
                show_message("Login OK", "login-ok", function() {
                    $("#login-dialog").parent().fadeOut(400, function() {
                        $("#login-dialog").dialog("close")
                        // clear fields for possible re-open
                        $("#login-username").val("")
                        $("#login-password").val("")
                        $("#login-message").text("")
                        // restore close box of the other dialogs
                        $(".ui-dialog-titlebar-close").show()
                    })
                })
                //
                login(username)
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

    this.handle_special_command = function(label) {
        if (label == "Login...") {
            $("#login-dialog").dialog("open")
        } else if (label == "Logout \"" + get_username() + "\"") {
            logout()
        }
    }

    // ---

    this.has_write_permission = function(topic) {
        return topic.permissions.write
    }

    this.has_create_permission = function(topic_type) {
        return topic_type.permissions.create
    }

    // ----------------------------------------------------------------------------------------------- Private Functions

    function login(username) {
        js.set_cookie("dm3_username", username)
        dm3c.ui.set_menu_item_label("special-menu", "loginout-item", "Logout \"" + get_username() + "\"")
        //
        adjust_create_widget()
    }

    function logout() {
        js.remove_cookie("dm3_username")
        dm3c.ui.set_menu_item_label("special-menu", "loginout-item", "Login...")
        //
        adjust_create_widget()
    }

    // ---

    function adjust_create_widget() {
        dm3c.reload_types()
        var menu = dm3c.recreate_type_menu("create-type-menu")
        if (menu.get_item_count()) {
            $("#create-widget").show()
        } else {
            $("#create-widget").hide()
        }
    }

    // ---

    function lookup_user(username, password) {
        var user = dm3c.restc.get_topic_by_property("de/deepamehta/core/property/username", username)
        if (user && user.properties["de/deepamehta/core/property/password"] == encrypt_password(password)) {
            return user
        }
    }

    function get_username() {
        return js.get_cookie("dm3_username")
    }

    function encrypt_password(password) {
        return ENCRYPTED_PASSWORD_PREFIX + SHA256(password)
    }
}
