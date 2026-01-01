jQuery(document).ready(function($) {
    if (typeof user_geo_vars === 'undefined' || !user_geo_vars.ajax_url) {
        return;
    }

    var initialCountryCode = user_geo_vars.initial_country_code;
    var ajaxUrl = user_geo_vars.ajax_url;

    $.ajax({
        url: ajaxUrl,
        type: 'POST',
        data: {
            action: 'verify_country'
        },
        success: function(response) {
            if (response.success && response.data.country_code !== initialCountryCode) {
                // אם יש אי התאמה, מפנים מחדש את הדף
                window.location.reload();
            }
        },
        error: function(xhr, status, error) {
            // טיפול בשגיאות ב-AJAX
            console.error("AJAX Error: " + status + " " + error);
        }
    });
});
