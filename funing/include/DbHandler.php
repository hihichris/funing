<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     * @param String $address User login address
     * @param String $phone User login phone
     */
    public function createUser($name, $email, $password,$address,$phone) {
        
        require_once 'PassHash.php';
        $response = array();
        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);
            

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(name, email, password_hash, api_key, status,address,phone,other1,other2) values(?, ?, ?, ?, 1,?,?,'','')");
            $stmt->bind_param("ssssss", $name, $email, $password_hash, $api_key,$address,$phone);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }

    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

    /**
     * Update user information
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     * @param String $address User login address
     * @param String $phone User login phone
     */
    public function updateUser($user_id, $name, $email, $password,$address,$phone) {
        
        require_once 'PassHash.php';
        $password_hash = PassHash::hash($password);
        $stmt = $this->conn->prepare("UPDATE users set name = ?, email = ?, password_hash= ?, address = ?, phone = ? WHERE uid = ?");
        $stmt->bind_param("sssssi", $name, $email, $password_hash,$address,$phone, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT uid from users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Checking for user exist or not
     * @param String $uid to check in db
     * @return boolean
     */
    private function isUserExistsById($uid) {
        $stmt = $this->conn->prepare("SELECT * from users WHERE uid = ?");
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT address, name, email, api_key, status, phone, other1, other2, created_at,uid FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($address, $name, $email, $api_key, $status, $phone, $other1, $other2, $created_at,$uid);
            $stmt->fetch();
            $user = array();
            $user["address"] = $address;
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["phone"] = $phone;
            $user["other1"] = $other1;
            $user["other2"] = $other2;
            $user["created_at"] = $created_at;
            $user["uid"] = $uid;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE uid = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT uid FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT uid from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /* ------------- `products` table method ------------------ */

    /**
     * Creating new product
     * @param String $p_code product code
     * @param String $p_name product name
     * @param String $p_description product description
     * @param Integer $p_quantity product quantity
     * @param Decimal $p_price product price
     * @param String $p_image_url product image
     * @param String $p_type product type
     */
    public function createProduct($p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type) {
        
        // First check if product code already existed in db
        if (!$this->isProductExists($p_code)) {

            $stmt = $this->conn->prepare("INSERT INTO products(p_code,p_name,p_description,p_quantity,p_price,p_image_url,p_type,p_other1,p_other2) VALUES(?,?,?,?,?,?,?,'','')");

            $stmt->bind_param("sssidss", $p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type);
            $result = $stmt->execute();
            $stmt->close();
            
            if ($result) {
                // product successfully inserted                
                return PRODUCT_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create product
                return PRODUCT_CREATE_FAILED;
            }
        }
        else{
            return PRODUCT_ALREADY_EXIST;
        }
    }
    
    /**
     * Checking for duplicate product by product code
     * @param String $p_code product code to check in db
     * @return boolean
     */
    private function isProductExists($p_code) {
        $stmt = $this->conn->prepare("SELECT p_code from products WHERE p_code = ?");
        $stmt->bind_param("s", $p_code);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

        /**
     * Fetching all products
     * @param String -
     */
    public function getAllProducts() {
        $products = array();
        $stmt = $this->conn->prepare("SELECT pid, p_code,p_name,p_description,p_quantity,p_price,p_image_url,p_type,p_created_at FROM products");

        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($pid, $p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type,$p_created_at);
            while ($stmt->fetch()){
                $res["pid"] = $pid;
                $res["p_code"] = $p_code;
                $res["p_name"] = $p_name;
                $res["p_description"] = $p_description;
                $res["p_quantity"] = $p_quantity;
                $res["p_price"] = $p_price;
                $res["p_image_url"] = $p_image_url;
                $res["p_created_at"] = $p_created_at;
                array_push($products, $res);
            }
            $stmt->close();
            return $products;
        } else {
            return NULL;
        }        
    }
    
            /**
     * Fetching product with pid
     * @param String -
     */
    public function getProduct($pid) {
        $products = array();
        $stmt = $this->conn->prepare("SELECT pid, p_code,p_name,p_description,p_quantity,p_price,p_image_url,p_type,p_created_at FROM products where pid=?");
        $stmt->bind_param("s", $pid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($pid, $p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type,$p_created_at);
            while ($stmt->fetch()){
                $res["pid"] = $pid;
                $res["p_code"] = $p_code;
                $res["p_name"] = $p_name;
                $res["p_description"] = $p_description;
                $res["p_quantity"] = $p_quantity;
                $res["p_price"] = $p_price;
                $res["p_image_url"] = $p_image_url;
                $res["p_created_at"] = $p_created_at;
                array_push($products, $res);
            }
            $stmt->close();
            return $products;
        } else {
            return NULL;
        }        
    }

    /**
     * Fetching all products with query string
     * @param String $p_type of the product
     */
    public function getProductsWithTypes($p_type) {
        $products = array();
        $stmt = $this->conn->prepare("SELECT pid, p_code,p_name,p_description,p_quantity,p_price,p_image_url,p_type,p_created_at FROM products where p_type LIKE CONCAT('%', ?, '%') ");
        $stmt->bind_param("s", $p_type);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($pid, $p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type,$p_created_at);
            while ($stmt->fetch()){
                $res["pid"] = $pid;
                $res["p_code"] = $p_code;
                $res["p_name"] = $p_name;
                $res["p_description"] = $p_description;
                $res["p_quantity"] = $p_quantity;
                $res["p_price"] = $p_price;
                $res["p_image_url"] = $p_image_url;
                $res["p_created_at"] = $p_created_at;
                array_push($products, $res);
            }
            $stmt->close();
            return $products;
        } else {
            return NULL;
        }        
    }
    
    /**
     * Updating product
     * @param String $p_code product code
     * @param String $p_name product name
     * @param String $p_description product description
     * @param Integer $p_quantity product quantity
     * @param Decimal $p_price product price
     * @param String $p_image_url product image
     * @param String $p_type product type
     */
    public function updateProduct($p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type) {
        $stmt = $this->conn->prepare("UPDATE products set p_name = ?, p_description= ?, p_quantity = ?, p_price =?, p_image_url = ?, p_type = ? WHERE p_code = ? ");
            $stmt->bind_param("ssidsss", $p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type,$p_code);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
   /* ------------- `coupons` table method ------------------ */

    /**
     * Creating new coupon
     * @param String $c_code coupon code
     * @param String $c_name coupon name
     * @param String $c_description coupon description
     * @param String $c_image_url coupon image url
     * @param String $c_discount_type coupon discount type, cash or percentage
     * @param Decimal $c_discount_detail coupon discount detail
     */
    public function createCoupon($c_code,$c_name,$c_description,$c_image_url,$c_discount_type,$c_discount_detail) {

        // First check if coupon code already existed in db
        if (!$this->isCouponExists($c_code)) {

            $stmt = $this->conn->prepare("INSERT INTO coupons(c_code,c_name,c_description,c_status,c_image_url,c_discount_type,c_discount_detail,c_other1,c_other2) VALUES(?,?,?,1,?,?,?,'','')");

            $stmt->bind_param("sssssd", $c_code,$c_name,$c_description,$c_image_url,$c_discount_type,$c_discount_detail);
            $result = $stmt->execute();
            $stmt->close();
            
            if ($result) {
                // coupon successfully inserted                
                return COUPON_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create coupon
                return COUPON_CREATE_FAILED;
            }
        }
        else{
            return COUPON_ALREADY_EXIST;
        }
    }

    /**
     * Fetching all coupons
     * @param String -
     */
    public function getAllCoupons() {
        $coupons = array();
        $stmt = $this->conn->prepare("SELECT cid, c_code,c_name,c_description,c_image_url,c_discount_type,c_discount_detail,c_created_at,c_status FROM coupons");

        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($cid, $c_code,$c_name,$c_description,$c_image_url,$c_discount_type,$c_discount_detail,$c_created_at,$c_status);
            while ($stmt->fetch()){
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["c_created_at"] = $c_created_at;
                $res["c_status"] = $c_status;
                array_push($coupons, $res);
            }
            $stmt->close();
            return $coupons;
        } else {
            return NULL;
        }        
    }
    
     /**
     * Fetching coupon with cid
     * @param String -
     */
    public function getCoupon($cid) {
        $coupons = array();
        $stmt = $this->conn->prepare("SELECT cid, c_code,c_name,c_description,c_image_url,c_discount_type,c_discount_detail,c_created_at,c_status FROM coupons where cid=?");
        $stmt->bind_param("s", $cid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($cid, $c_code,$c_name,$c_description,$c_image_url,$c_discount_type,$c_discount_detail,$c_created_at,$c_status);
            while ($stmt->fetch()){
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["c_created_at"] = $c_created_at;
                $res["c_status"] = $c_status;
                array_push($coupons, $res);
            }
            $stmt->close();
            return $coupons;
        } else {
            return NULL;
        }        
    }

    
    /**
     * Checking for duplicate coupon by coupon code
     * @param String $c_code product code to check in db
     * @return boolean
     */
    private function isCouponExists($c_code) {
        $stmt = $this->conn->prepare("SELECT c_code from coupons WHERE c_code = ?");
        $stmt->bind_param("s", $c_code);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Checking for duplicate coupon by coupon code
     * @param String $c_code product code to check in db
     * @return boolean
     */
    private function isCouponExistsById($cid) {
        $stmt = $this->conn->prepare("SELECT c_code from coupons WHERE cid = ?");
        $stmt->bind_param("i", $cid);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /* ------------- `user_coupons` table method ------------------ */

    /**
     * Creating new user
     * @param String $cid coupon id
     * @param String $uid user id
     * @param String $uc_expired_at User login password
     */
    public function createUserCoupon($cid,$uid,$uc_expired_at) {
        
        $response = array();
        
        //should check it's a valid datetime or not YYYY-MM-DD HH:MM:SS'
        if (!$this->isValidDate($uc_expired_at)) {
            return USERCOUPON_EXPIRYDATE_NOT_VALID;
        }
        
        // First check if user already existed in db
        if ($this->isUserExistsById($uid)) {
                if ($this->isCouponExistsById($cid)) {
                                // insert query
                    $stmt = $this->conn->prepare("INSERT INTO user_coupons(cid,oid,uc_expired_at,uc_status,uid) values(?, '', ?, 'Valid', ?)");
                    $stmt->bind_param("isi", $cid, $uc_expired_at, $uid);

                    $result = $stmt->execute();

                    $stmt->close();

                    // Check for successful insertion
                    if ($result) {
                        // User_coupon successfully inserted
                        return USERCOUPON_CREATED_SUCCESSFULLY;
                    } else {
                        // Failed to create user_coupon
                        return USERCOUPON_CREATE_FAILED;
                    }
                }
                else{
                    //coupon not exist on coupons table
                    return USERCOUPON_COUPON_NOTEXIST;
                }
        } else {
            // User not exist on user table
            return USERCOUPON_UID_NOTEXIST;
        }

        return $response;
    }
    
    function isValidDate($data) {
        if (date('Y-m-d H:i:s', strtotime($data)) == $data) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Fetching all user coupons 
     * @param String $user_id id of the user
     */
    public function getAllUserCoupons($user_id) {

        $usercoupons = array();
        $stmt = $this->conn->prepare("SELECT u.ucid, u.oid, u.uc_expired_at, u.uc_status,u.cid, c.c_code, c.c_name, c.c_description, c.c_discount_type,c.c_discount_detail, c.c_image_url,u.uid from user_coupons u, coupons c WHERE u.cid = c.cid AND u.uid = ?");
        
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($ucid, $oid, $uc_expired_at, $uc_status,$cid,$c_code,$c_name,$c_description,$c_discount_type,$c_discount_detail,$c_image_url,$uid);
            while ($stmt->fetch()){
                $res["ucid"] = $ucid;
                $res["oid"] = $oid;
                $res["uc_expired_at"] = $uc_expired_at;
                $res["uc_status"] = $uc_status;
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["uid"] = $uid;
                array_push($usercoupons, $res);
            }
            $stmt->close();
            return $usercoupons;
        } else {
            return NULL;
        }        
    }
    
    /**
     * Fetching user coupon binded with a particular order 
     * @param String $order id of the user
     */
    public function getBindedUserCoupon($oid) {

        $usercoupons = array();
        $stmt = $this->conn->prepare("SELECT u.ucid, u.oid, u.uc_expired_at, u.uc_status,u.cid, c.c_code, c.c_name, c.c_description, c.c_discount_type,c.c_discount_detail, c.c_image_url,u.uid from user_coupons u, coupons c WHERE u.cid = c.cid AND u.oid = ?");
        
        $stmt->bind_param("i", $oid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($ucid, $oid, $uc_expired_at, $uc_status,$cid,$c_code,$c_name,$c_description,$c_discount_type,$c_discount_detail,$c_image_url,$uid);
            while ($stmt->fetch()){
                $res["ucid"] = $ucid;
                $res["oid"] = $oid;
                $res["uc_expired_at"] = $uc_expired_at;
                $res["uc_status"] = $uc_status;
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["uid"] = $uid;
                array_push($usercoupons, $res);
            }
            $stmt->close();
            return $usercoupons;
        } else {
            return NULL;
        }        
    }

    /**
     * Fetching a particular user coupons 
     * @param String $user_id id of the user
     * @param String $ucid id of the user coupon
     */
    public function getUserCoupon($user_id,$ucid) {

        $usercoupons = array();
        $stmt = $this->conn->prepare("SELECT u.ucid, u.oid, u.uc_expired_at, u.uc_status,u.cid, c.c_code, c.c_name, c.c_description, c.c_discount_type,c.c_discount_detail, c.c_image_url,u.uid from user_coupons u, coupons c WHERE u.cid = c.cid AND u.uid = ? AND u.ucid = ?");
        
        $stmt->bind_param("ii", $user_id,$ucid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($ucid, $oid, $uc_expired_at, $uc_status,$cid,$c_code,$c_name,$c_description,$c_discount_type,$c_discount_detail,$c_image_url,$uid);
            while ($stmt->fetch()){
                $res["ucid"] = $ucid;
                $res["oid"] = $oid;
                $res["uc_expired_at"] = $uc_expired_at;
                $res["uc_status"] = $uc_status;
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["uid"] = $uid;
                array_push($usercoupons, $res);
            }
            $stmt->close();
            return $usercoupons;
        } else {
            return NULL;
        }        
    }
    
    /**
     * Fetching all user coupons with status 
     * @param String $user_id id of the user
     */
    public function getUserCouponWithStatus($user_id, $uc_status) {

        $usercoupons = array();
        $stmt = $this->conn->prepare("SELECT u.ucid, u.oid, u.uc_expired_at, u.uc_status,u.cid, c.c_code, c.c_name, c.c_description, c.c_discount_type,c.c_discount_detail, c.c_image_url,u.uid from user_coupons u, coupons c WHERE u.cid = c.cid AND u.uid = ? AND u.uc_status=?");
        
        $stmt->bind_param("is", $user_id,$uc_status);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($ucid, $oid, $uc_expired_at, $uc_status,$cid,$c_code,$c_name,$c_description,$c_discount_type,$c_discount_detail,$c_image_url,$uid);
            while ($stmt->fetch()){
                $res["ucid"] = $ucid;
                $res["oid"] = $oid;
                $res["uc_expired_at"] = $uc_expired_at;
                $res["uc_status"] = $uc_status;
                $res["cid"] = $cid;
                $res["c_code"] = $c_code;
                $res["c_name"] = $c_name;
                $res["c_description"] = $c_description;
                $res["c_image_url"] = $c_image_url;
                $res["c_discount_type"] = $c_discount_type;
                $res["c_discount_detail"] = $c_discount_detail;
                $res["uid"] = $uid;
                array_push($usercoupons, $res);
            }
            $stmt->close();
            return $usercoupons;
        } else {
            return NULL;
        }        
    }    
    
    /**
     * Checking for user coupon exist or not
     * @param String $ucid ucid to check in db
     * @param String $user_id uid to check in db
     * @return boolean
     */
    public function isUserCouponValidById($user_id, $ucid) {
        $stmt = $this->conn->prepare("SELECT * from user_coupons WHERE ucid = ? AND uid = ? AND uc_status = 'Valid'");
        $stmt->bind_param("ii", $ucid, $user_id);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Updating user coupon status
     * @param String $user_id id of the user
     * @param String $ucid id of the user coupon
     * @param String $uc_status user coupon status
     * @param String $oid which order the user coupon used to
     */
    public function updateUserCoupon($user_id, $ucid, $uc_status,$oid) {
        $stmt = $this->conn->prepare("UPDATE user_coupons set uc_status = ?, oid = ? WHERE uid = ? AND ucid= ?");
        $stmt->bind_param("siii", $uc_status, $oid, $user_id, $ucid);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    
    /* ------------- `shoppingcart` table method ------------------ */

    /**
     * Creating new shoppingcart
     * @param -
     */
   public function createShoppingCart($user_id) {
        // First check if user ID already existed in db
        $stmt = $this->conn->prepare("INSERT INTO shoppingcart(s_status,uid) VALUES('Valid',?)");
        $stmt->bind_param("i", $user_id);
        $result = $stmt->execute();
        $stmt->close();
       
        if ($result) {
            // shoppingcart row created
            $new_shoppingcart_id = $this->conn->insert_id;
            return $new_shoppingcart_id;
        } else {
            // shoppingcart failed to create
            return NULL;
        }       
    }
    
    
    /**
     * Fetching all user shoppingcart 
     * @param String $user_id id of the user
     */
    public function getAllUserShoppingCart($user_id) {
        
        $shoppingcarts = array();
        $shoppingcartdetails = array();
        $shoppingcartwithdetails = array();
        $stmt = $this->conn->prepare("SELECT sid, s_amount, s_created_at, s_status, uid FROM shoppingcart WHERE uid = ? ");
        
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($sid, $s_amount, $s_created_at, $s_status, $uid);
            while ($stmt->fetch()){
                $res["sid"] = $sid;
                $res["s_amount"] = $s_amount;
                $res["s_created_at"] = $s_created_at;
                $res["s_status"] = $s_status;
                $res["uid"] = $uid;
                $res["shoppingcartdetails"] = $shoppingcartdetails;
                array_push($shoppingcarts, $res);
            }
            $stmt->close();
        } else {
            return NULL;
        } 
        
        //bind the details into shoppingcart
        foreach ($shoppingcarts as $shoppingcart){
            $shoppingcart["shoppingcartdetails"] = $this->getShoppingCartDetails($shoppingcart["sid"]);
            array_push($shoppingcartwithdetails, $shoppingcart);
        }
        return $shoppingcartwithdetails;
    }
    
    /**
     * Fetching all user shoppingcart 
     * @param String $user_id id of the user
     */
    public function getAllUserShoppingCartQuery($user_id,$s_status) {
        
        $shoppingcarts = array();
        $shoppingcartdetails = array();
        $shoppingcartwithdetails = array();
        $stmt = $this->conn->prepare("SELECT sid, s_amount, s_created_at, s_status, uid FROM shoppingcart WHERE uid = ? AND s_status = ?");
        
        $stmt->bind_param("is", $user_id,$s_status);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($sid, $s_amount, $s_created_at, $s_status, $uid);
            while ($stmt->fetch()){
                $res["sid"] = $sid;
                $res["s_amount"] = $s_amount;
                $res["s_created_at"] = $s_created_at;
                $res["s_status"] = $s_status;
                $res["uid"] = $uid;
                $res["shoppingcartdetails"] = $shoppingcartdetails;
                array_push($shoppingcarts, $res);
            }
            $stmt->close();
        } else {
            return NULL;
        } 
        
        //bind the details into shoppingcart
        foreach ($shoppingcarts as $shoppingcart){
            $shoppingcart["shoppingcartdetails"] = $this->getShoppingCartDetails($shoppingcart["sid"]);
            array_push($shoppingcartwithdetails, $shoppingcart);
        }
        return $shoppingcartwithdetails;
    }
    
    /**
     * Checking for shoppingcart id exist or not
     * @param String $sid to check in db
     * @return boolean
     */
    private function isShoppingCartExistsById($sid) {
        $stmt = $this->conn->prepare("SELECT * from shoppingcart WHERE sid = ? AND s_status='Valid' ");
        $stmt->bind_param("i", $sid);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Updating shoppingcart
     * @param String $sid id of the shoppingcart
     * @param String $s_status shoppingcart 
     * @param String $s_amount shoppingcart 
     */
    public function updateShoppingcart($user_id, $sid, $s_status, $s_amount) {
        $stmt = $this->conn->prepare("UPDATE shoppingcart set s_status = ?, s_amount = ? WHERE uid= ? AND sid = ?");
        $stmt->bind_param("sdii", $s_status, $s_amount, $user_id, $sid);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
   
    
  /* ------------- `shoppingcart_detail` table method ------------------ */

    /**
     * Creating new shoppingcart_detail
     * @param - pid,p_code,p_description, p_name, p_price, sd_quantity, sd_subamount,sid
     */
   public function createShoppingCartDetail($pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid) {
        // First check if shoppingcart ID already existed in db
        if ($this->isShoppingCartExistsById($sid)) {
            $stmt = $this->conn->prepare("INSERT INTO shoppingcart_detail(pid,p_code,p_description, p_name, p_price, sd_quantity, sd_subamount,sid) VALUES(?,?,?,?,?,?,?,?)");
            $stmt->bind_param("isssdidi", $pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid);
            $result = $stmt->execute();
            $stmt->close();

            if ($result) {
                // shoppingcart_detail row created
                $new_shoppingcartdetail_id = $this->conn->insert_id;
                
                //should do it in server or not ???
                // update the amount of corresponding shopping cart
                /*$stmt = $this->conn->prepare("UPDATE shoppingcart SET s_amount = s_amount + ? where sid = ?");
                $stmt->bind_param("di", $sd_subamount, $sid);
                $result = $stmt->execute();*/
                
                return $new_shoppingcartdetail_id;
            } else {
                // shoppingcart failed to create
                return NULL;
            }               
        }
        else{
            return -1;
        }
    
    }
    
    /**
     * Fetching a particular shoppingcart details
     * @param String $sid id of the shoppingcart
     */
    public function getShoppingCartDetails($sid) {

        $shoppingcartdetails = array();
        $stmt = $this->conn->prepare("SELECT shoppingcart_detail.pid,shoppingcart_detail.p_code,shoppingcart_detail.p_description,shoppingcart_detail.p_name,shoppingcart_detail.p_price,shoppingcart_detail.sdid,shoppingcart_detail.sd_created_at,shoppingcart_detail.sd_quantity,shoppingcart_detail.sd_subamount,shoppingcart_detail.sid,products.p_image_url from shoppingcart_detail,products WHERE sid = ? and shoppingcart_detail.pid = products.pid");
        
        $stmt->bind_param("i", $sid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($pid,$p_code,$p_description,$p_name,$p_price,$sdid,$sd_created_at,$sd_quantity,$sd_subamount,$sid,$p_image_url);
            while ($stmt->fetch()){
                $res["pid"] = $pid;
                $res["p_code"] = $p_code;
                $res["p_description"] = $p_description;
                $res["p_name"] = $p_name;
                $res["p_price"] = $p_price;
                $res["p_image_url"] = $p_image_url;
                $res["sdid"] = $sdid;
                $res["sd_created_at"] = $sd_created_at;
                $res["sd_quantity"] = $sd_quantity;
                $res["sd_subamount"] = $sd_subamount;
                $res["sid"] = $sid;
                array_push($shoppingcartdetails, $res);
            }
            $stmt->close();
            return $shoppingcartdetails;
        } else {
            return NULL;
        }        
    }
    
    /**
     * Updating shoppingcart_detail
     * @param String $pid id of product of the shoppingcart_detail
     * @param String $p_code shoppingcart_detail 
     * @param String $p_description shoppingcart_detail
     * @param String $p_name shoppingcart_detail
     * @param String $p_price shoppingcart_detail
     * @param String $sd_quantity shoppingcart_detail
     * @param String $sd_subamount shoppingcart_detail
     * @param String $sid shoppingcart_detail
     */
    public function updateShoppingcartDetail($pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid,$sdid) {
        $stmt = $this->conn->prepare("UPDATE shoppingcart_detail set pid = ?, p_code = ?, p_description = ?, p_name = ?, p_price = ?, sd_quantity = ?, sd_subamount =?  WHERE sid= ? AND sdid = ?");
        $stmt->bind_param("isssdidii", $pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid,$sdid);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    /**
     * Deleting a shoppingcart details
     * @param String $task_id id of the task to delete
     */
    public function deleteShoppingCartDetail($user_id, $sdid) {
        $stmt = $this->conn->prepare("DELETE FROM shoppingcart_detail WHERE sdid = ? ");
        $stmt->bind_param("i", $sdid);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
    /* ------------- `orders` table method ------------------ */

    /**
     * Creating new order
     * @param -
     */
   public function createOrder($address, $email, $name, $o_amount, $phone, $ucid,$user_id) {
        // First check if user ID already existed in db
        $stmt = $this->conn->prepare("INSERT INTO orders(address, email,name, o_amount, o_status, phone, ucid,uid) VALUES(?,?,?,?,'Valid',?,?,?)");
        $stmt->bind_param("sssdsii", $address, $email, $name, $o_amount, $phone, $ucid,$user_id);
        $result = $stmt->execute();
        $stmt->close();
              
        if ($result) {
            // order row created
            $order_id = $this->conn->insert_id;
            if ($ucid > 0){
                //Update the usercoupon record as the user used a coupon
                $this->updateUserCoupon($user_id, $ucid, 'Used',$order_id);
                //Invalid the shoppingcart as the items has moved to order
            }
            
            return $order_id;
        } else {
            // order failed to create
            return NULL;
        }       
    }
    
    /**
     * Checking for order id exist or not
     * @param String $oid to check in db
     * @return boolean
     */
    private function isOrderExistsById($oid) {
        $stmt = $this->conn->prepare("SELECT * from orders WHERE oid = ? ");
        $stmt->bind_param("i", $oid);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Fetching all user orders 
     * @param String $user_id id of the user
     */
    public function getAllUserOrders($user_id) {
        
        $orders = array();
        $orderdetails = array();
        $orderwithdetails = array();
        $stmt = $this->conn->prepare("SELECT oid, o_amount, o_created_at, o_status, uid,name, email, address,phone FROM orders WHERE uid = ? ");
        
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($oid, $o_amount, $o_created_at, $o_status, $uid,$name,$email,$address,$phone);
            while ($stmt->fetch()){
                $res["oid"] = $oid;
                $res["o_amount"] = $o_amount;
                $res["o_created_at"] = $o_created_at;
                $res["o_status"] = $o_status;
                $res["uid"] = $uid;
                $res["name"] = $name;
                $res["email"] = $email;
                $res["address"] = $address;
                $res["phone"] = $phone;
                $res["orderdetails"] = $orderdetails;
                array_push($orders, $res);
            }
            $stmt->close();
        } else {
            return NULL;
        } 
        
        //bind the details into order
        foreach ($orders as $order){
            $order["orderdetails"] = $this->getOrderDetails($order["oid"]);
            $order["usercoupondetails"] = $this->getBindedUserCoupon($order["oid"]);
            array_push($orderwithdetails, $order);
        }
        return $orderwithdetails;
    }
    
    /**
     * Fetching all user orders 
     * @param String $user_id id of the user
     * @param String $oid id of the user
     */
    public function getUserOrder($user_id,$oid) {
        
        $orders = array();
        $orderdetails = array();
        $orderwithdetails = array();
        $stmt = $this->conn->prepare("SELECT oid, o_amount, o_created_at, o_status, uid,name, email, address,phone FROM orders WHERE uid = ? AND oid = ? ");
        
        $stmt->bind_param("ii", $user_id,$oid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($oid, $o_amount, $o_created_at, $o_status, $uid,$name,$email,$address,$phone);
            while ($stmt->fetch()){
                $res["oid"] = $oid;
                $res["o_amount"] = $o_amount;
                $res["o_created_at"] = $o_created_at;
                $res["o_status"] = $o_status;
                $res["uid"] = $uid;
                $res["name"] = $name;
                $res["email"] = $email;
                $res["address"] = $address;
                $res["phone"] = $phone;
                $res["orderdetails"] = $orderdetails;
                array_push($orders, $res);
            }
            $stmt->close();
        } else {
            return NULL;
        } 
        
        //bind the details into order
        foreach ($orders as $order){
            $order["orderdetails"] = $this->getOrderDetails($order["oid"]);
            $order["usercoupondetails"] = $this->getBindedUserCoupon($order["oid"]);
            array_push($orderwithdetails, $order);
        }
        return $orderwithdetails;
    }
    
    /**
     * Updating order
     * @param String $oid id of the order
     * @param String $o_status order 
     * @param String $o_amount order 
     */
    public function updateOrder($user_id, $oid, $o_status, $o_amount) {
        $stmt = $this->conn->prepare("UPDATE orders set o_status = ?, o_amount = ? WHERE uid= ? AND oid = ?");
        $stmt->bind_param("sdii", $o_status, $o_amount, $user_id, $oid);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }
    
      /* ------------- `orders_detail` table method ------------------ */

    /**
     * Creating new orders_detail
     * @param - pid,p_code,p_description, p_name, p_price, od_quantity, od_subamount,oid
     */
   public function createOrderDetail($pid,$p_code,$p_description, $p_name, $p_price, $od_quantity, $od_subamount,$oid) {
        // First check if order ID already existed in db
        if ($this->isOrderExistsById($oid)) {
            $stmt = $this->conn->prepare("INSERT INTO orders_detail(pid,p_code,p_description, p_name, p_price, od_quantity, od_subamount,oid) VALUES(?,?,?,?,?,?,?,?)");
            $stmt->bind_param("isssdidi", $pid,$p_code,$p_description, $p_name, $p_price, $od_quantity, $od_subamount,$oid);
            $result = $stmt->execute();
            $stmt->close();

            if ($result) {
                // shoppingcart_detail row created
                $new_orderdetail_id = $this->conn->insert_id;
                
                //should do it in server or not ???
                // update the amount of corresponding shopping cart
                /*$stmt = $this->conn->prepare("UPDATE orders SET o_amount = o_amount + ? where oid = ?");
                $stmt->bind_param("di", $sd_subamount, $sid);
                $result = $stmt->execute();*/
                
                return $new_orderdetail_id;
            } else {
                // orderdetails failed to create
                return NULL;
            }               
        }
        else{
            return -1;
        }
    
    }
    
    /**
     * Fetching a particular order details
     * @param String $oid id of the order
     */
    public function getOrderDetails($oid) {

        $orderdetails = array();
        $stmt = $this->conn->prepare("SELECT orders_detail.pid,orders_detail.p_code,orders_detail.p_description,orders_detail.p_name,orders_detail.p_price,odid,orders_detail.od_created_at,orders_detail.od_quantity,orders_detail.od_subamount,orders_detail.oid, products.p_image_url from orders_detail, products WHERE oid = ? and orders_detail.pid = products.pid");
        
        $stmt->bind_param("i", $oid);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($pid,$p_code,$p_description,$p_name,$p_price,$odid,$od_created_at,$od_quantity,$od_subamount,$oid, $p_image_url);
            while ($stmt->fetch()){
                $res["pid"] = $pid;
                $res["p_code"] = $p_code;
                $res["p_description"] = $p_description;
                $res["p_name"] = $p_name;
                $res["p_price"] = $p_price;
                $res["p_image_url"] = $p_image_url;
                $res["odid"] = $odid;
                $res["od_created_at"] = $od_created_at;
                $res["od_quantity"] = $od_quantity;
                $res["od_subamount"] = $od_subamount;
                $res["oid"] = $oid;
                array_push($orderdetails, $res);
            }
            $stmt->close();
            return $orderdetails;
        } else {
            return NULL;
        }        
    }
    
    /* ------------- `tasks` table method ------------------ */

    /**
     * Creating new task
     * @param String $user_id user id to whom task belongs to
     * @param String $task task text
     */
    public function createTask($user_id, $task) {
        $stmt = $this->conn->prepare("INSERT INTO tasks(task) VALUES(?)");
        $stmt->bind_param("s", $task);
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
            // task row created
            // now assign the task to user
            $new_task_id = $this->conn->insert_id;
            $res = $this->createUserTask($user_id, $new_task_id);
            if ($res) {
                // task created successfully
                return $new_task_id;
            } else {
                // task failed to create
                return NULL;
            }
        } else {
            // task failed to create
            return NULL;
        }
    }

    /**
     * Fetching single task
     * @param String $task_id id of the task
     */
    public function getTask($task_id, $user_id) {
        $stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        
        $stmt->bind_param("ii", $task_id, $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $task, $status, $created_at);
            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["id"] = $id;
            $res["task"] = $task;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching all user tasks
     * @param String $user_id id of the user
     */
    public function getAllUserTasks($user_id) {
 /*       $stmt = $this->conn->prepare("SELECT t.* FROM tasks t, user_tasks ut WHERE t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $tasks = $stmt->get_result();
        $stmt->close();
        return $tasks;*/
        $tasks = array();
        $stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $task, $status, $created_at);
            while ($stmt->fetch()){
                $res["id"] = $id;
                $res["task"] = $task;
                $res["status"] = $status;
                $res["created_at"] = $created_at;
                array_push($tasks, $res);
            }
            $stmt->close();
            return $tasks;
        } else {
            return NULL;
        }        
    }

    /**
     * Updating task
     * @param String $task_id id of the task
     * @param String $task task text
     * @param String $status task status
     */
    public function updateTask($user_id, $task_id, $task, $status) {
        $stmt = $this->conn->prepare("UPDATE tasks t, user_tasks ut set t.task = ?, t.status = ? WHERE t.id = ? AND t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("siii", $task, $status, $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Deleting a task
     * @param String $task_id id of the task to delete
     */
    public function deleteTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- `user_tasks` table method ------------------ */

    /**
     * Function to assign a task to user
     * @param String $user_id id of the user
     * @param String $task_id id of the task
     */
    public function createUserTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, task_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $task_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }

}

?>
