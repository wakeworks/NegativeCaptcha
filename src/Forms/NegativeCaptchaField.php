<?php
namespace WakeWorks\NegativeCaptcha\Forms;

use SilverStripe\Forms\FormField;
use Illuminate\Encryption\Encrypter;
use SilverStripe\Control\Controller;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\TextField;
use SilverStripe\Forms\FieldGroup;

class NegativeCaptchaField extends FormField {

    private $minTimeInSeconds = 10;
    private $maxTimeInSeconds = 60 * 60;

    public function Field($properties = []) {
        $encrypter = $this->getEncrypter();
        $timestamp = time();

        $timestampField = HiddenField::create(
            $this->name . '_ts',
            $this->name . '_ts',
            $encrypter->encryptString($timestamp)
        );

        $honeypotField = TextField::create(
            $this->name . '_tf',
            $this->name . '_tf'
        );

        $honeypotField->setFieldHolderTemplate('WakeWorks\\NegativeCaptcha\\Forms\\NegativeCaptchaTextFieldHolder');
        $honeypotField->setSmallFieldHolderTemplate('WakeWorks\\NegativeCaptcha\\Forms\\NegativeCaptchaTextFieldHolder');

        return FieldGroup::create([
            $timestampField,
            $honeypotField
        ]);
    }

    public function validate($validator) {
        $encrypter = $this->getEncrypter();
        
        $honeypotFieldValue = Controller::curr()->getRequest()->requestVar($this->name . '_tf');
        $timestampFieldValue = Controller::curr()->getRequest()->requestVar($this->name . '_ts');
        if(!empty($honeypotFieldValue) || empty($timestampFieldValue)) {
            $this->addValidationError($validator);
            return false;
        }

        try {
            $timestampValue = intval($encrypter->decryptString($timestampFieldValue));
            $minTime = $timestampValue + $this->minTimeInSeconds;
            $maxTime = $timestampValue + $this->maxTimeInSeconds;

            if(time() < $minTime || time() > $maxTime) {
                $this->addValidationError($validator);
                return false;
            }
        } catch(\Exception $e) {
            $this->addValidationError($validator);
            return false;
        }

        return true;
    }

    private function addValidationError($validator) {
        $validator->validationError(
            $this->name,
            'Rejected.'
        );
    }

    private function getEncrypter() {
        return new Encrypter(
            $this->getSecretHash(),
            'aes-256-cbc'
        );
    }

    private function getSecretHash() {
        return hash_pbkdf2(
            'sha256',
            $this->getSecretKey(),
            $this->getSalt(),
            10000,
            32,
            true
        );
    }

    private function getSecretKey() {
        $session = Controller::curr()->getRequest()->getSession();
        
        $secretKey = $session->get(__CLASS__ . '.secretKey');
        if(!$secretKey) {
            $secretKey = random_bytes(32);
            $session->set(__CLASS__ . '.secretKey', $secretKey);
        }

        return $secretKey;
    }

    private function getSalt() {
        $session = Controller::curr()->getRequest()->getSession();
        
        $salt = $session->get(__CLASS__ . '.salt');
        if(!$salt) {
            $salt = random_bytes(32);
            $session->set(__CLASS__ . '.salt', $salt);
        }

        return $salt;
    }

}