#set($url = $xwiki.getURL("GoogleApps.Login", "view"))

function loginWithXWiki() {
    jQuery(".panel .panel-body dl").show()
    return false;
}

require(['jquery', 'xwiki-events-bridge', 'xwiki-meta'], function($, xm) {
    $(document).ready(function(event, data) {
        if (XWiki.contextaction == "login" || XWiki.contextaction == "loginsubmit" ) {
            jQuery('<div id="googleapps-login-choice">'
                + '<div class="col-xs-12" style="margin-bottom: 20px; padding: 20px;">'
                + '<a href="${url}?' + location.href.substring(location.href.indexOf("?"))
                + '" class="btn btn-primary col-xs-12" '
                + ' style="background:white; border: #3F76DF solid 2px; color: #808080; font-family: Roboto Medium,Roboto,sans-serif; font-weight: bold; text-align:left;"'
                + ' ><img  alt="Logo Google" src="${xwiki.getAttachmentURL('GoogleApps.WebHome','google-logo.png')}" style="height:1.2em">&nbsp;&nbsp;'
                + '${escapetool.javascript($services.localization.render("googleapps.login.withgoogle"))}</a>'
                + '<div class="col-xs-12"></div>'
                + '<a href="javascript:void(0)" onclick="return loginWithXWiki()" class="btn btn-primary col-xs-12"'
                + ' style="text-align:left; background: white; color: #808080; font-weight:bold; border: #808080 2px solid; "'
                + '  ><img alt="Logo XWiki" src="${xwiki.getAttachmentURL('GoogleApps.WebHome','xwiki-logo.png')}" style="height:1.2em;margin-bottom:0.2em">&nbsp;&nbsp;'
                + '${escapetool.javascript($services.localization.render("googleapps.login.withxwiki"))}</a></div>'
                + '<div style="clear: both;"></div></div>').insertBefore(jQuery(".panel .panel-body dl"))
        }
        if (XWiki.contextaction != "loginsubmit") {
            jQuery(".panel .panel-body dl").hide();
        }
    }); // end document ready

}); // end requirejs
