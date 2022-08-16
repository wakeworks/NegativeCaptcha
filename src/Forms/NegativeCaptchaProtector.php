<?php
namespace WakeWorks\NegativeCaptcha\Forms;

use SilverStripe\SpamProtection\SpamProtector;

class NegativeCaptchaProtector implements SpamProtector {

    public function getFormField($name = "NegativeCaptchaField", $title = 'Captcha', $value = null) {
        return NegativeCaptchaField::create($name, $title);
    }

    public function setFieldMapping($fieldMapping) {
    }
}