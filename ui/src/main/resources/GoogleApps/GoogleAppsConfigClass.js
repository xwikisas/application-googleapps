require(['jquery'], function (jQuery) {

  var prefix = '#GoogleApps\\.GoogleAppsConfigClass_0_';

  //deactivating
  function deactivate(elts) {
    elts.each(function () {
      jQuery(jQuery(this).closest('dl')).find('label').css('color','darkgrey');
      this.wasDisabled = jQuery(this).prop('disabled');
      jQuery(this).prop('disabled', true);
    });
  }


  // reactivating
  function reactivate(elements) {
    jQuery(elements).each(function () {
      if (typeof (this.wasDisabled)) {
        jQuery(jQuery(this).closest('dl')).find('label').css('color','black');
        jQuery(this).prop('disabled', this.wasDisabled);
      }
    });
  }


  // updaters
  function updateAllInputs() {
    if (this.checked) {
      reactivate(allInputs);
    } else {
      deactivate(allInputs);
    }
  }

  function updateCookieFields() {
    if (this.checked) {
      reactivate(cookieInputs);
    } else {
      deactivate(cookieInputs);
    }
  }

  function updateDomainHint() {
    if (typeof(this.value)=='undefined') return;
    var domainHint = jQuery('#googleapps-domain-livehint');
    var valid = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(this.value);
    if (this.value.length > 0) {
      if (valid) {
        domainHint.text(hintTextOn.replace('\{0\}', this.value));
        domainHint.removeClass('warningmessage');
      } else {
        domainHint.text(hintTextInvaliddomain.replace('\{0\}', this.value));
        domainHint.addClass('warningmessage');
      }
    } else {
      domainHint.text(hintTextOff);
      domainHint.removeClass('warningmessage');
    }
  }


  var allInput, cookieInputs;
  var hintTextOn = "${escapetool.javascript($services.localization.render('GoogleApps.GoogleAppsConfigClass_domain.hintTextOn'))}",
      hintTextOff = "${escapetool.javascript($services.localization.render('GoogleApps.GoogleAppsConfigClass_domain.hintTextOff'))}",
      hintTextInvaliddomain = "${escapetool.javascript($services.localization.render('GoogleApps.GoogleAppsConfigClass_domain.hintTextInvaliddomain'))}";

  function updateScopes() {
    var scopes = "";
    jQuery(("input[name^='scope_']")).each(function() {
      if(jQuery.attr(this, "disabled")!=="disabled" && this.checked)
        scopes = scopes + " " + this.name.substring('scope_'.length);
    });
    jQuery("input[name$='_scope']").val(scopes);
    updateDriveNowWhat();
  }

  function readScopes() {
    var scope = jQuery("input[name$='_scope']").val();
    jQuery(("input[name^='scope_']")).each(function() {
      if(jQuery.attr(this, "disabled")!=="disabled") {
        var n = this.name.substring('scope_'.length);
        if (scope.indexOf(n) > -1) {
          this.checked = true;
        } else {
          this.checked = false;
        }
      }
    });
    updateDriveNowWhat();
  }

  function updateDriveNowWhat() {
    var driveInput = jQuery("input[name='scope_drive']")[0];
    if(driveInput.checked) jQuery("#driveOnNowWhat").show();
    else jQuery("#driveOnNowWhat").hide();
  }

  (function () {
    // register listeners
    cookieInputs = jQuery(prefix + 'skipLoginPage, ' + prefix + 'authWithCookies, ' + prefix + 'cookiesTTL');
    jQuery(prefix + 'useCookies').each(updateCookieFields).change(updateCookieFields);

    var keepThem = "name$=\'_activate\'],[name=\'formactionsac\'],[name=\'form_token\'],"
      + "[name=\'xcontinue\'],[name=\'xredirect\'";

    allInputs = jQuery(
      '#googleapps_GoogleApps\\.GoogleAppsConfig input:not(['+keepThem+'])');
    jQuery(prefix + 'activate').each(updateAllInputs).change(updateAllInputs);

    jQuery(prefix + 'domain').each(updateDomainHint).on('change keyup', updateDomainHint);

    jQuery(("input[name^='scope_']")).each(function() {
      jQuery(this).change(function() { updateScopes(); });
    });
    readScopes();

    jQuery('#googleapps_GoogleApps\.GoogleAppsConfig').submit(cancelCancelEdit);
  }).defer();
});
