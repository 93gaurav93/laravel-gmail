<?php

namespace Dacastro4\LaravelGmail;

use Dacastro4\LaravelGmail\Traits\Configurable;
use Google_Client;
use Google_Service_Gmail;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Storage;

class GmailConnection extends Google_Client
{

    use Configurable {
        __construct as configConstruct;
    }

    protected $emailAddress;
    protected $refreshToken;
    protected $app;
    protected $accessToken;
    protected $token;
    private $configuration;
    public $userId;

    public function __construct($config = null, $userId = null)
    {
        $this->app = Container::getInstance();

        $this->userId = $userId;

        $this->configConstruct($config);

        $this->configuration = $config;

        parent::__construct($this->getConfigs());

        $this->configApi();

        if ($this->checkPreviouslyLoggedIn()) {
            $this->refreshTokenIfNeeded();
        }

    }

    /**
     * Check and return true if the user has previously logged in without checking if the token needs to refresh
     *
     * @return bool
     */
    public function checkPreviouslyLoggedIn()
    {
        if (auth()->check()) {
            $user = auth()->user();
            $allowJsonEncrypt = $this->_config['gmail.allow_json_encrypt'];

            if ($allowJsonEncrypt) {
                $savedConfigToken = json_decode(decrypt($user->access_token), true);
            } else {
                $savedConfigToken = json_decode($user->access_token, true);
            }
            $this->setAccessToken($savedConfigToken);

            return !empty($savedConfigToken['access_token']);
        }

        return false;
    }

    /**
     * Refresh the auth token if needed
     *
     * @return mixed|null
     */
    private function refreshTokenIfNeeded()
    {
        if ($this->isAccessTokenExpired()) {
            $this->fetchAccessTokenWithRefreshToken($this->getRefreshToken());
            $token = $this->getAccessToken();
            $this->setBothAccessToken($token);

            return $token;
        }

        return $this->token;
    }

    /**
     * Check if token exists and is expired
     * Throws an AuthException when the auth file its empty or with the wrong token
     *
     *
     * @return bool Returns True if the access_token is expired.
     */
    public function isAccessTokenExpired()
    {
        $token = $this->getToken();

        if ($token) {
            $this->setAccessToken($token);
        }

        return parent::isAccessTokenExpired();
    }

    public function getToken()
    {
        return parent::getAccessToken() ?: $this->config();
    }

    public function setToken($token)
    {
        $this->setAccessToken($token);
    }

    public function getAccessToken()
    {
        $token = parent::getAccessToken() ?: $this->config();

        return $token;
    }

    /**
     * @param array|string $token
     */
    public function setAccessToken($token)
    {
        parent::setAccessToken($token);
    }

    /**
     * @param $token
     * @throws \Exception
     */
    public function setBothAccessToken($token)
    {
        $this->setAccessToken($token);
        $this->saveAccessToken($token);
    }

    /**
     * Save the credentials for user
     *
     * @param array $config
     * @throws \Exception
     */
    public function saveAccessToken(array $config)
    {
        $allowJsonEncrypt = $this->_config['gmail.allow_json_encrypt'];
        $config['email'] = $this->emailAddress;

        if (empty($config['email'])) {
            if ($allowJsonEncrypt) {
                $savedConfigToken = json_decode(decrypt(auth()->user()->access_token), true);
            } else {
                $savedConfigToken = json_decode(auth()->user()->access_token, true);
            }
            if (isset($savedConfigToken['email'])) {
                $config['email'] = $savedConfigToken['email'];
            }
        }

        if (class_exists($this->_config['gmail.user_model'])) {
            $userModel = $this->_config['gmail.user_model'];
            if ($user = $userModel::where('email', $config['email'])->first()) {
                if ($allowJsonEncrypt) {
                    $user->access_token = encrypt(json_encode($config));
                } else {
                    $user->access_token = json_encode($config);
                }
                $user->save();
            } else {
                throw new \Exception('User not found');
            }
        } else {
            throw new \Exception('User model not found');
        }

    }

    /**
     * @return array|string
     * @throws \Exception
     */
    public function makeToken()
    {
        if (!$this->check()) {
            $request = Request::capture();
            $code = (string)$request->input('code', null);
            if (!is_null($code)) {
                $accessToken = $this->fetchAccessTokenWithAuthCode($code);
                if ($this->haveReadScope()) {
                    $me = $this->getProfile();
                    if (property_exists($me, 'emailAddress') && class_exists($this->_config['gmail.user_model'])) {
                        $userModel = $this->_config['gmail.user_model'];
                        $newUser = null;
                        $user = $userModel::where('email', $me->emailAddress)->first();
                        if (!$user) {
                            $user = new $userModel();
                            $user->name = explode('@', $me->emailAddress)[0];
                            $user->email = $me->emailAddress;
                            $user->save();
                            $newUser = $user;
                        }
                        $this->emailAddress = $me->emailAddress;
                        $accessToken['email'] = $me->emailAddress;

                        $this->setBothAccessToken($accessToken);
                        $watch = $this->watch('me');
                        if ($newUser) {
                            $newUser->history_id = $watch->historyId;
                            $newUser->save();
                        }

                        $accessToken['logged_in'] = auth()->login($user, true);
                        return $accessToken;
                    }
                }
            }
            throw new \Exception('No access token');
        } else {
            return $this->getAccessToken();
        }
    }

    /**
     * Check
     *
     * @return bool
     */
    public function check()
    {
        return !$this->isAccessTokenExpired();
    }

    /**
     * Gets user profile from Gmail
     *
     * @return \Google_Service_Gmail_Profile
     */
    public function getProfile()
    {
        $service = new Google_Service_Gmail($this);

        return $service->users->getProfile('me');
    }


    /**
     * Set up or update a push notification watch on the given user mailbox.
     *
     * @param string $userId The user's email address. The special value `me` can be
     * used to indicate the authenticated user.
     * @param array $labelIds
     *
     * @return \Google_Service_Gmail_WatchResponse
     */
    public function watch(string $userId = 'me', array $labelIds = ['INBOX'])
    {
        $service = new Google_Service_Gmail($this);

        $watch = new \Google_Service_Gmail_WatchRequest();
        $watch->topicName = $this->_config['gmail.pub_sub_topic_name'];
        $watch->labelIds = $labelIds;

        return $service->users->watch($userId, $watch);
    }


    /**
     * Stop receiving push notifications for the given user mailbox. (users.stop)
     *
     * @param string $userId The user's email address. The special value `me` can be
     * used to indicate the authenticated user.
     * @param array $optParams Optional parameters.
     *
     * @return \expectedClass|\Google_Http_Request
     */
    public function stop(string $userId, array $optParams = array())
    {
        $service = new Google_Service_Gmail($this);

        return $service->users->stop($userId, []);
    }

    /**
     * Revokes user's permission and logs them out
     */
    public function logout()
    {
        $this->revokeToken();
    }

    /**
     * Delete the credentials for a user
     */
    public function deleteAccessToken()
    {
        if (auth()->check()) {

            $user = auth()->user();
            $allowJsonEncrypt = $this->_config['gmail.allow_json_encrypt'];

            if ($allowJsonEncrypt) {
                $user->access_token = encrypt(json_encode([]));
            } else {
                $user->access_token = json_encode([]);
            }
        } else {
            abort(401);
        }
    }

    private function haveReadScope()
    {
        $scopes = $this->getUserScopes();

        return in_array(Google_Service_Gmail::GMAIL_READONLY, $scopes);
    }


}
