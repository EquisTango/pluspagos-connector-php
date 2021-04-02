<?php
namespace PPConnectorSDK\Package;

class Package
{
    public function GetPackage ($body, $phrase, $token = "", $optEncript = false)
    {
        if (property_exists($body, "Hash"))
        {
            $body->{"Hash"} = $this->HashString($body);
        }
        if ($optEncript)
        {
            $this->EncryptPaymentData($body, $token);
        }
        $body_String = json_encode($body);
        return $this->EncryptAES256($body_String, $phrase);
    }

    private function HashString($model)
    {
        return $this->HashSHA256($model);
    }

    private function EncryptAES256($body, $phrase)
    {
        return $this->EncryptString($body, $phrase);
    }

    private function EncryptPaymentData($body, $token)
    {
        return $this->EncryptData($body, $token);
    }

    private function HashSHA256 ($model)
    {
        $input = "";
        foreach (get_object_vars($model) as $key => $mod){
            if ($mod == null)
            {
                continue;
            }
            else if ($key == "Hash")
            {
                continue;
            }
            else if (is_object($mod))
            {
                $properties = get_object_vars($mod);
                $json_model = json_decode(json_encode($mod), true);
                foreach (array_keys($properties) as $val)
                {
                    $values = sprintf("%s*", $json_model[$val]);
                    $input = sprintf("%s%s", $input, $values);
                }
            }
            else if (is_array($mod)){
                foreach (array_values($mod) as $val)
                {
                    $values = sprintf("%s*", $val);
                    $input = sprintf("%s%s", $input, $values);
                }
            }
            else {
                $input = sprintf("%s%s*", $input, $mod);
            }
        }
        $input_bytes = utf8_encode(substr($input, 0, -1));
        $hash_byte = unpack('C*', hash( "sha256", $input_bytes, true));
        $string = null;
        for ($i = 1; $i <= count($hash_byte); $i++) 
        {
            $string .= str_pad(strtolower(dechex($hash_byte[$i])), 2, '0', STR_PAD_LEFT);
        }
        return $string;
    }

    private function EncryptString($plainText, $phrase)
    {
        if(strlen($phrase) < 32)
        {
            while(strlen($phrase) < 32)
            {
                $phrase .= $phrase;
            }
            $phrase = substr($phrase,0,32);
        }
        if(strlen($phrase) > 32)
        {
            $phrase = substr($phrase,0,32);	   
        }
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $string = openssl_encrypt($plainText,"aes-256-cbc",$phrase, OPENSSL_RAW_DATA , $iv);
        return base64_encode($iv.$string);
    }

    public function EncryptData ($body, $token)
    {
        $encryptKey = substr($token, 12, 8);
        foreach (get_object_vars($body) as $key => $mod)
        {
            if ($mod == null)
            {
                continue;
            }
            else if (is_object($mod) && strpos(get_class($mod), "DatosTarjeta") == true)
            {
                $properties = get_object_vars($mod);
                $json_model = json_decode(json_encode($mod), true);
                foreach (array_keys($properties) as $val)
                {
                    if ($val == "Email")
                    {
                        continue;
                    }
                    $values = $this->EncryptString($json_model[$val], $encryptKey);
                    $body->$key->$val = $values;
                }
            }
        }
        return $body;
    }
}
