<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();
        
        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = 1;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = 1;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password, address, phone
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password','address','phone'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $address = $app->request->post('address');
            $phone = $app->request->post('phone');
            
            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($name, $email, $password,$address,$phone);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = 0;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = 1;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = 1;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            //var_dump($app->request()->post('email'));
            //return;
            //$json = $app->request->getBody();
            //$data = json_decode($json, true);
            //echo $data['email'];
            //return;

            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = 0;
                    $response['address'] = $user['address'];
                    $response['uid'] = $user['uid'];
                    $response['name'] = $user['name'];
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['phone'] = $user['phone'];
                    $response['other1'] = $user['other1'];
                    $response['other2'] = $user['other2'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = 1;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = 1;
                $response['message'] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });


/**
 * Updating user information
 * method PUT
 * params name, email, password, address, phone
 * url - /register
 */
$app->put('/register', 'authenticate', function() use($app) {
            // check for required params
            
            verifyRequiredParams(array('name', 'email', 'password','address','phone'));

            global $user_id;
            // reading post params
            $name = $app->request->put('name');
            $email = $app->request->put('email');
            $password = $app->request->put('password');
            $address = $app->request->put('address');
            $phone = $app->request->put('phone');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUser($user_id,$name, $email, $password,$address,$phone);
            if ($result) {
                // task updated successfully
                $response["error"] = 0;
                $response["message"] = "User information updated successfully";
            } else {
                // task failed to update
                $response["error"] = 1;
                $response["message"] = "User information failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * Product creation
 * url - /products
 * method - POST
 * params - p_code,p_name,p_description,p_quantity,p_price,p_image_url,p_type
 */
$app->post('/products', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('p_code', 'p_name', 'p_description','p_quantity','p_price','p_image_url','p_type'));

            $response = array();
                
            // reading post params
            $p_code = $app->request->post('p_code');
            $p_name = $app->request->post('p_name');
            $p_description = $app->request->post('p_description');
            $p_quantity = $app->request->post('p_quantity');
            $p_price = $app->request->post('p_price');
            $p_image_url = $app->request->post('p_image_url');
            $p_type = $app->request->post('p_type');
            

            $db = new DbHandler();
            $res = $db->createProduct($p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type);

            if ($res == PRODUCT_CREATED_SUCCESSFULLY) {
                $response["error"] = 0;
                $response["message"] = "You are successfully created the product";
            } else if ($res == PRODUCT_CREATE_FAILED) {
                $response["error"] = 1;
                $response["message"] = "Oops! An error occurred while creating the product";
            } else if ($res == PRODUCT_ALREADY_EXIST) {
                $response["error"] = 1;
                $response["message"] = "Sorry, the product code already exist";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing all products
 * method GET
 * url /products          
 */
$app->get('/products', function() use ($app) {
    
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getAllProducts(); 
            $response["error"] = 0;
            $response["products"] = array();
            foreach ($result as $product) {
                $tmp = array();
                $tmp["pid"] = $product["pid"];
                $tmp["p_code"] = $product["p_code"];
                $tmp["p_name"] = $product["p_name"];
                $tmp["p_description"] = $product["p_description"];
                $tmp["p_quantity"] = $product["p_quantity"];
                $tmp["p_price"] = $product["p_price"];
                $tmp["p_image_url"] = $product["p_image_url"];
                $tmp["p_createdAt"] = $product["p_created_at"];
                array_push($response["products"], $tmp);
            }
            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing product with id
 * method GET
 * url /products          
 */
$app->get('/products/:id', function($pid) use ($app) {
    
            $response = array();
            $db = new DbHandler();
            // fetching product with id
            $result = $db->getProduct($pid); 
            $response["error"] = false;
            $response["products"] = array();
            foreach ($result as $product) {
                $tmp = array();
                $tmp["pid"] = $product["pid"];
                $tmp["p_code"] = $product["p_code"];
                $tmp["p_name"] = $product["p_name"];
                $tmp["p_description"] = $product["p_description"];
                $tmp["p_quantity"] = $product["p_quantity"];
                $tmp["p_price"] = $product["p_price"];
                $tmp["p_image_url"] = $product["p_image_url"];
                $tmp["p_createdAt"] = $product["p_created_at"];
                array_push($response["products"], $tmp);
            }
            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing products with product types
 * method GET
 * url /productsWithTypes          
 */
$app->get('/productsWithTypes/:type', function($p_type) use ($app) {    
            $response = array();
            $db = new DbHandler();
            // fetching all products
            $result = $db->getProductsWithTypes($p_type); 
            $response["error"] = false;
            $response["products"] = array();
            foreach ($result as $product) {
                $tmp = array();
                $tmp["pid"] = $product["pid"];
                $tmp["p_code"] = $product["p_code"];
                $tmp["p_name"] = $product["p_name"];
                $tmp["p_description"] = $product["p_description"];
                $tmp["p_quantity"] = $product["p_quantity"];
                $tmp["p_price"] = $product["p_price"];
                $tmp["p_image_url"] = $product["p_image_url"];
                $tmp["p_createdAt"] = $product["p_created_at"];
                array_push($response["products"], $tmp);
            }
            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing products with product types critera
 * method GET
 * url /productsQuery          
 */
$app->get('/productsQuery', function() use ($app) {  
            $p_type = $app->request->get('p_type');
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getProductsWithTypes($p_type); 
            $response["error"] = false;
            $response["products"] = array();
            foreach ($result as $product) {
                $tmp = array();
                $tmp["pid"] = $product["pid"];
                $tmp["p_code"] = $product["p_code"];
                $tmp["p_name"] = $product["p_name"];
                $tmp["p_description"] = $product["p_description"];
                $tmp["p_quantity"] = $product["p_quantity"];
                $tmp["p_price"] = $product["p_price"];
                $tmp["p_image_url"] = $product["p_image_url"];
                $tmp["p_createdAt"] = $product["p_created_at"];
                array_push($response["products"], $tmp);
            }
            echoRespnse(200, $response);
        });

/**
 * Updating Product 
 * method PUT
 * params oid, o_status, o_amount
 * url - /orders
 */
$app->put('/products', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('p_code', 'p_name', 'p_description','p_quantity','p_price','p_image_url','p_type'));

            $response = array();
                
            // reading post params
            $p_code = $app->request->post('p_code');
            $p_name = $app->request->post('p_name');
            $p_description = $app->request->post('p_description');
            $p_quantity = $app->request->post('p_quantity');
            $p_price = $app->request->post('p_price');
            $p_image_url = $app->request->post('p_image_url');
            $p_type = $app->request->post('p_type');

            global $user_id;    
            $db = new DbHandler();
            $response = array();


            // updating product
            $result = $db->updateProduct($p_code,$p_name,$p_description,$p_quantity,$p_price,$p_image_url,$p_type);
            if ($result) {
                // product updated successfully
                $response["error"] = 0;
                $response["message"] = "Product updated successfully";
            } else {
                // product failed to update
                $response["error"] = 1;
                $response["message"] = "Product failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * Coupon creation
 * url - /coupons
 * method - POST
 * params - c_code,c_name,c_description,c_image_url,c_discount_type,c_discount_detail
 */
$app->post('/coupons', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('c_code', 'c_name', 'c_description','c_image_url','c_discount_type','c_discount_detail'));

            $response = array();
                
            // reading post params
            $c_code = $app->request->post('c_code');
            $c_name = $app->request->post('c_name');
            $c_description = $app->request->post('c_description');
            $c_image_url = $app->request->post('c_image_url');
            $c_discount_type = $app->request->post('c_discount_type');
            $c_discount_detail = $app->request->post('c_discount_detail');
            
    
            $db = new DbHandler();
            $res = $db->createCoupon($c_code,$c_name,$c_description,$c_image_url,$c_discount_type,$c_discount_detail);

            if ($res == COUPON_CREATED_SUCCESSFULLY) {
                $response["error"] = 0;
                $response["message"] = "You are successfully created the coupon";
            } else if ($res == COUPON_CREATE_FAILED) {
                $response["error"] = 1;
                $response["message"] = "Oops! An error occurred while creating the coupon";
            } else if ($res == COUPON_ALREADY_EXIST) {
                $response["error"] = 1;
                $response["message"] = "Sorry, the coupon code already exist";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing all coupons
 * method GET
 * url /coupons          
 */
$app->get('/coupons', function() use ($app) {
    
            $response = array();
            $db = new DbHandler();
            // fetching all coupons
            $result = $db->getAllCoupons(); 
            $response["error"] = false;
            $response["coupons"] = array();
            foreach ($result as $coupon) {
                $tmp = array();
                $tmp["cid"] = $coupon["cid"];
                $tmp["c_code"] = $coupon["c_code"];
                $tmp["c_name"] = $coupon["c_name"];
                $tmp["c_description"] = $coupon["c_description"];
                $tmp["c_image_url"] = $coupon["c_image_url"];
                $tmp["c_discount_type"] = $coupon["c_discount_type"];
                $tmp["c_discount_detail"] = $coupon["c_discount_detail"];
                $tmp["c_created_at"] = $coupon["c_created_at"];
                $tmp["c_status"] = $coupon["c_status"];
                array_push($response["coupons"], $tmp);
            }
            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITHOUT AUTHENTICATION ------------------------
 */

/**
 * Listing coupon with id
 * method GET
 * url /products          
 */
$app->get('/coupons/:id', function($cid) use ($app) {
            $response = array();
            $db = new DbHandler();
            // fetching coupon with id
            $result = $db->getCoupon($cid); 
            $response["error"] = false;
            $response["coupons"] = array();
            foreach ($result as $coupon) {
                $tmp = array();
                $tmp["cid"] = $coupon["cid"];
                $tmp["c_code"] = $coupon["c_code"];
                $tmp["c_name"] = $coupon["c_name"];
                $tmp["c_description"] = $coupon["c_description"];
                $tmp["c_image_url"] = $coupon["c_image_url"];
                $tmp["c_discount_type"] = $coupon["c_discount_type"];
                $tmp["c_discount_detail"] = $coupon["c_discount_detail"];
                $tmp["c_created_at"] = $coupon["c_created_at"];
                $tmp["c_status"] = $coupon["c_status"];
                array_push($response["coupons"], $tmp);
            }
            echoRespnse(200, $response);
        });



/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * UserCoupon creation
 * url - /usercoupons
 * method - POST
 * params - cid, uid, uc_expired_at
 */
$app->post('/usercoupons', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('cid', 'uid', 'uc_expired_at'));

            $response = array();
                
            // reading post params
            $cid = $app->request->post('cid');
            $uid = $app->request->post('uid');
            $uc_expired_at = $app->request->post('uc_expired_at');       
                
            $db = new DbHandler();
            $res = $db->createUserCoupon($cid,$uid,$uc_expired_at);

            if ($res == USERCOUPON_CREATED_SUCCESSFULLY) {
                $response["error"] = 0;
                $response["message"] = "You are successfully created the usercoupon";
            } else if ($res == USERCOUPON_CREATE_FAILED) {
                $response["error"] = 1;
                $response["message"] = "Oops! An error occurred while creating the usercoupon";
            } else if ($res == USERCOUPON_UID_NOTEXIST) {
                $response["error"] = 1;
                $response["message"] = "Sorry, the user not exist";
            } else if ($res == USERCOUPON_COUPON_NOTEXIST) {
                $response["error"] = 1;
                $response["message"] = "Sorry, the coupon not exist";
            } else if ($res == USERCOUPON_EXPIRYDATE_NOT_VALID) {
                $response["error"] = 1;
                $response["message"] = "Please input a valid expiry date";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

/**
 * Listing all user_coupons of particual user
 * method GET
 * url /usercoupons          
 */
$app->get('/usercoupons', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user coupons
    
            $result = $db->getAllUserCoupons($user_id); 
            $response["error"] = false;
            $response["usercoupons"] = array();
            foreach ($result as $usercoupon) {
                $tmp = array();
                $tmp["ucid"] = $usercoupon["ucid"];
                $tmp["oid"] = $usercoupon["oid"];
                $tmp["uc_expired_at"] = $usercoupon["uc_expired_at"];
                $tmp["uc_status"] = $usercoupon["uc_status"];
                $tmp["cid"] = $usercoupon["cid"];
                $tmp["c_code"] = $usercoupon["c_code"];
                $tmp["c_name"] = $usercoupon["c_name"];
                $tmp["c_description"] = $usercoupon["c_description"];
                $tmp["c_image_url"] = $usercoupon["c_image_url"];
                $tmp["c_discount_type"] = $usercoupon["c_discount_type"];
                $tmp["c_discount_detail"] = $usercoupon["c_discount_detail"];
                $tmp["uid"] = $usercoupon["uid"];
                array_push($response["usercoupons"], $tmp);
            }
            echoRespnse(200, $response);
    
        });

/**
 * Listing a particular user_coupon of particular user
 * method GET
 * url /usercoupons/:id 
  * params - ucid
 */

$app->get('/usercoupons/:id', 'authenticate', function($ucid) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
    
            $result = $db->getUserCoupon($user_id,$ucid); 
            $response["error"] = false;
            $response["usercoupons"] = array();
            foreach ($result as $usercoupon) {
                $tmp = array();
                $tmp["ucid"] = $usercoupon["ucid"];
                $tmp["oid"] = $usercoupon["oid"];
                $tmp["uc_expired_at"] = $usercoupon["uc_expired_at"];
                $tmp["uc_status"] = $usercoupon["uc_status"];
                $tmp["cid"] = $usercoupon["cid"];
                $tmp["c_code"] = $usercoupon["c_code"];
                $tmp["c_name"] = $usercoupon["c_name"];
                $tmp["c_description"] = $usercoupon["c_description"];
                $tmp["c_image_url"] = $usercoupon["c_image_url"];
                $tmp["c_discount_type"] = $usercoupon["c_discount_type"];
                $tmp["c_discount_detail"] = $usercoupon["c_discount_detail"];
                $tmp["uid"] = $usercoupon["uid"];
                array_push($response["usercoupons"], $tmp);
            }
            echoRespnse(200, $response);
    
        });


/**
 * Updating existing usercoupon
 * method PUT
 * params uc_status, oid
 * url - /usercoupons/:id
 */
$app->put('/usercoupons/:id', 'authenticate', function($ucid) use($app) {
            // check for required params
            verifyRequiredParams(array('uc_status','oid'));
    
            //#TODO should include the part that check the order is exist or not

            global $user_id;            
            $uc_status = $app->request->put('uc_status');
            $oid = $app->request->put('oid');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateUserCoupon($user_id, $ucid, $uc_status,$oid);
            if ($result) {
                // usercoupon updated successfully
                $response["error"] = 0;
                $response["message"] = "Usercoupon status updated successfully, binded to a order";
            } else {
                // usercoupon failed to update
                $response["error"] = 1;
                $response["message"] = "Usercoupon status failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Listing usercoupon with critera
 * method GET
 * url /usercouponsQuery          
 */
$app->get('/usercouponsQuery', 'authenticate', function() use ($app) {  
            $uc_status = $app->request->get('uc_status');
             global $user_id;  
            $response = array();
            $db = new DbHandler();
            // fetching user coupon
            $result = $db->getUserCouponWithStatus($user_id,$uc_status); 
            $response["error"] = false;
            $response["usercoupons"] = array();
            foreach ($result as $usercoupon) {
                $tmp = array();
                $tmp["ucid"] = $usercoupon["ucid"];
                $tmp["oid"] = $usercoupon["oid"];
                $tmp["uc_expired_at"] = $usercoupon["uc_expired_at"];
                $tmp["uc_status"] = $usercoupon["uc_status"];
                $tmp["cid"] = $usercoupon["cid"];
                $tmp["c_code"] = $usercoupon["c_code"];
                $tmp["c_name"] = $usercoupon["c_name"];
                $tmp["c_description"] = $usercoupon["c_description"];
                $tmp["c_image_url"] = $usercoupon["c_image_url"];
                $tmp["c_discount_type"] = $usercoupon["c_discount_type"];
                $tmp["c_discount_detail"] = $usercoupon["c_discount_detail"];
                $tmp["uid"] = $usercoupon["uid"];
                array_push($response["usercoupons"], $tmp);
            }
            echoRespnse(200, $response);
        });


/**
 * ----------- METHODS WITH AUTHENTICATION ---------------------------------
 */
/**
 * shoppingcart creation
 * url - /shoppingcart
 * method - POST
 * params - 
 */
$app->post('/shoppingcart', 'authenticate', function() use($app) {
            global $user_id;         
            $db = new DbHandler();
            // creating new shoppingcart
            $shoppingcart_id = $db->createShoppingCart($user_id);
    
            if ($shoppingcart_id != NULL) {
                $response["error"] = 0;
                $response["message"] = "Shoppingcart created successfully";
                $response["sid"] = $shoppingcart_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = 1;
                $response["message"] = "Failed to create shoppingcart. Please try again";
                echoRespnse(200, $response);
            }  
        });

/**
 * Listing all shoppingcart of particular user
 * method GET
 * url /shoppingcart          
 */
$app->get('/shoppingcart', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user shoppingcart
                
            $result = $db->getAllUserShoppingCart($user_id); 
    
            $response["error"] = 0;
            $response["shoppingcarts"] = array();
            foreach ($result as $shoppingcart) {
                $tmp = array();
                $tmp["sid"] = $shoppingcart["sid"];
                $tmp["s_amount"] = $shoppingcart["s_amount"];
                $tmp["s_created_at"] = $shoppingcart["s_created_at"];
                $tmp["s_status"] = $shoppingcart["s_status"];
                $tmp["uid"] = $shoppingcart["uid"];
                $tmp["shoppingcartdetails"] = $shoppingcart["shoppingcartdetails"];
                array_push($response["shoppingcarts"], $tmp);
            }
    
            echoRespnse(200, $response);
    
        });

/**
 * Listing all shoppingcart with status of particular user
 * method GET
 * url /shoppingcartQuery          
 */
$app->get('/shoppingcartQuery', 'authenticate', function() use($app) {
            $s_status = $app->request->get('s_status');
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user shoppingcart
            $result = $db->getAllUserShoppingCartQuery($user_id,$s_status); 
    
            $response["error"] = 0;
            $response["shoppingcarts"] = array();
            foreach ($result as $shoppingcart) {
                $tmp = array();
                $tmp["sid"] = $shoppingcart["sid"];
                $tmp["s_amount"] = $shoppingcart["s_amount"];
                $tmp["s_created_at"] = $shoppingcart["s_created_at"];
                $tmp["s_status"] = $shoppingcart["s_status"];
                $tmp["uid"] = $shoppingcart["uid"];
                $tmp["shoppingcartdetails"] = $shoppingcart["shoppingcartdetails"];
                array_push($response["shoppingcarts"], $tmp);
            }
    
            echoRespnse(200, $response);
    
        });

/**
 * Updating shoppingcart 
 * method PUT
 * params sid, s_status, s_amount
 * url - /shoppingcart
 */
$app->put('/shoppingcart', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('sid', 's_status','s_amount'));

            global $user_id;    
    
            $sid = $app->request->put('sid');
            $s_status = $app->request->put('s_status');
            $s_amount = $app->request->put('s_amount');
            $db = new DbHandler();
            $response = array();


            // updating shoppingcart
            $result = $db->updateShoppingcart($user_id, $sid, $s_status, $s_amount);
            if ($result) {
                // shoppingcart updated successfully
                $response["error"] = 0;
                $response["message"] = "Shoppingcart updated successfully";
            } else {
                // shoppingcart failed to update
                $response["error"] = 1;
                $response["message"] = "Shoppingcart failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * shoppingcart_detail creation
 * url - /shoppingcart_detail
 * method - POST
 * params - pid,p_code,p_description, p_name, p_price, sd_quantity, sd_subamount,sid
 */
$app->post('/shoppingcart_detail', 'authenticate', function() use($app) {
            verifyRequiredParams(array('pid', 'p_code', 'p_description','p_name','p_price','sd_quantity','sd_subamount','sid'));

            $response = array();
                
            // reading post params
            $pid = $app->request->post('pid');
            $p_code = $app->request->post('p_code');
            $p_description = $app->request->post('p_description');
            $p_name = $app->request->post('p_name');
            $p_price = $app->request->post('p_price');
            $sd_quantity = $app->request->post('sd_quantity');
            $sd_subamount = $app->request->post('sd_subamount');
            $sid = $app->request->post('sid');
    
            global $user_id;         
            $db = new DbHandler();
            // creating new shoppingcart
            $shoppingcart_detail_id = $db->createShoppingCartDetail($pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid);
    
            if ($shoppingcart_detail_id == -1) {
                $response["error"] = 1;
                $response["message"] = "The shoppingcart not exist. Please try again";
                echoRespnse(200, $response);                
            }
            else if ($shoppingcart_detail_id != NULL) {
                $response["error"] = 0;
                $response["message"] = "Shoppingcart detail created successfully";
                $response["sdid"] = $shoppingcart_detail_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = 1;
                $response["message"] = "Failed to create shoppingcart detail. Please try again";
                echoRespnse(200, $response);
            }  
        });

/**
 * Updating shoppingcart_detail 
 * method PUT
 * params pid,p_code,p_description, p_name, p_price, sd_quantity, sd_subamount,sid
 * url - /shoppingcart
 */
$app->put('/shoppingcart_detail', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('pid', 'p_code', 'p_description','p_name','p_price','sd_quantity','sd_subamount','sid','sdid'));
    
            global $user_id;    
            $pid = $app->request->put('pid');
            $p_code = $app->request->put('p_code');
            $p_description = $app->request->put('p_description');
            $p_name = $app->request->put('p_name');
            $p_price = $app->request->put('p_price');
            $sd_quantity = $app->request->put('sd_quantity');
            $sd_subamount = $app->request->put('sd_subamount');
            $sid = $app->request->put('sid');
            $sdid = $app->request->put('sdid');
    
            $db = new DbHandler();
            $response = array();


            // updating shoppingcart
            $result = $db->updateShoppingcartDetail($pid,$p_code,$p_description, $p_name, $p_price, $sd_quantity, $sd_subamount,$sid,$sdid);
            if ($result) {
                // shoppingcart updated successfully
                $response["error"] = 0;
                $response["message"] = "Shoppingcart_detail updated successfully";
            } else {
                // shoppingcart failed to update
                $response["error"] = 1;
                $response["message"] = "Shoppingcart_detail failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting shoppingcartdetail. Users can delete only shoppingcart detail
 * method DELETE
 * url /tasks
 */
$app->delete('/shoppingcart_detail/:id', 'authenticate', function($sdid) use($app) {
            global $user_id;
            $db = new DbHandler();
            $response = array();
            $result = $db->deleteShoppingCartDetail($user_id, $sdid);
            if ($result) {
                // task deleted successfully
                $response["error"] = 0;
                $response["message"] = "ShoppingCartDetail deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = 1;
                $response["message"] = "ShoppingCartDetail failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * ----------- METHODS WITH AUTHENTICATION ---------------------------------
 */
/**
 * order creation
 * url - /orders
 * method - POST
 * params - address, email, name, o_amount, o_status, phone, ucid
 */
$app->post('/orders', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('address', 'email', 'name', 'o_amount', 'phone', 'ucid'));

            $response = array();
                
            // reading post params
            $address = $app->request->post('address');
            $email = $app->request->post('email');
            $name = $app->request->post('name'); 
            $o_amount = $app->request->post('o_amount');
            $phone = $app->request->post('phone');
            $ucid = $app->request->post('ucid');
             global $user_id;         
            $db = new DbHandler();
    
    
            //need to check ucid that for the user is exist in the db and valid or not
            
            if ($ucid == 0 || $db->isUserCouponValidById($user_id,$ucid)){
                // creating new order
                $order_id = $db->createOrder($address, $email, $name, $o_amount, $phone, $ucid,$user_id);

                if ($order_id != NULL) {
                    $response["error"] = 0;
                    $response["message"] = "Order created successfully";
                    $response["oid"] = $order_id;
                    echoRespnse(201, $response);
                } else {
                    $response["error"] = 1;
                    $response["message"] = "Failed to create order. Please try again";
                    echoRespnse(200, $response);
                }  
            }
            else{
                    $response["error"] = 1;
                    $response["message"] = "Failed to create order. User coupon not valid";
                    echoRespnse(200, $response);
            }
        });

/**
 * Listing all orders of particular user
 * method GET
 * url /orders          
 */
$app->get('/orders', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user shoppingcart
                
            $result = $db->getAllUserOrders($user_id); 
    
            $response["error"] = 0;
            $response["orders"] = array();
            foreach ($result as $order) {
                $tmp = array();
                $tmp["oid"] = $order["oid"];
                $tmp["o_amount"] = $order["o_amount"];
                $tmp["o_created_at"] = $order["o_created_at"];
                $tmp["o_status"] = $order["o_status"];
                $tmp["uid"] = $order["uid"];
                $tmp["name"] = $order["name"];
                $tmp["email"] = $order["email"];
                $tmp["address"] = $order["address"];
                $tmp["phone"] = $order["phone"];
                $tmp["usercoupondetails"] = $order["usercoupondetails"];
                $tmp["orderdetails"] = $order["orderdetails"];
                array_push($response["orders"], $tmp);
            }
    
            echoRespnse(200, $response);
    
        });

/**
 * Listing a particular orders of particular user
 * method GET
 * url /orders          
 */
$app->get('/ordersQuery', 'authenticate', function() use($app){
            $oid = $app->request->get('oid');
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user shoppingcart
                
            $result = $db->getUserOrder($user_id,$oid); 
    
            $response["error"] = 0;
            $response["orders"] = array();
            foreach ($result as $order) {
                $tmp = array();
                $tmp["oid"] = $order["oid"];
                $tmp["o_amount"] = $order["o_amount"];
                $tmp["o_created_at"] = $order["o_created_at"];
                $tmp["o_status"] = $order["o_status"];
                $tmp["uid"] = $order["uid"];
                $tmp["name"] = $order["name"];
                $tmp["email"] = $order["email"];
                $tmp["address"] = $order["address"];
                $tmp["phone"] = $order["phone"];
                $tmp["usercoupondetails"] = $order["usercoupondetails"];
                $tmp["orderdetails"] = $order["orderdetails"];
                array_push($response["orders"], $tmp);
            }
    
            echoRespnse(200, $response);
    
        });

/**
 * Updating order 
 * method PUT
 * params oid, o_status, o_amount
 * url - /orders
 */
$app->put('/orders', 'authenticate', function() use($app) {
            // check for required params
            verifyRequiredParams(array('oid', 'o_status','o_amount'));

            global $user_id;    
    
            $oid = $app->request->put('oid');
            $o_status = $app->request->put('o_status');
            $o_amount = $app->request->put('o_amount');
            $db = new DbHandler();
            $response = array();


            // updating order
            $result = $db->updateOrder($user_id, $oid, $o_status, $o_amount);
            if ($result) {
                // order updated successfully
                $response["error"] = 0;
                $response["message"] = "Order updated successfully";
            } else {
                // order failed to update
                $response["error"] = 1;
                $response["message"] = "Order failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * orders_detail creation
 * url - /orders_detail
 * method - POST
 * params - pid,p_code,p_description, p_name, p_price, od_quantity, od_subamount,oid
 */
$app->post('/orders_detail', 'authenticate', function() use($app) {
            verifyRequiredParams(array('pid', 'p_code', 'p_description','p_name','p_price','od_quantity','od_subamount','oid'));

            $response = array();
                
            // reading post params
            $pid = $app->request->post('pid');
            $p_code = $app->request->post('p_code');
            $p_description = $app->request->post('p_description');
            $p_name = $app->request->post('p_name');
            $p_price = $app->request->post('p_price');
            $od_quantity = $app->request->post('od_quantity');
            $od_subamount = $app->request->post('od_subamount');
            $oid = $app->request->post('oid');
    
            global $user_id;         
            $db = new DbHandler();
            // creating new orderdetail
            $order_detail_id = $db->createOrderDetail($pid,$p_code,$p_description, $p_name, $p_price, $od_quantity, $od_subamount,$oid);
    
            if ($order_detail_id == -1) {
                $response["error"] = 1;
                $response["message"] = "The order not exist. Please try again";
                echoRespnse(200, $response);                
            }
            else if ($order_detail_id != NULL) {
                $response["error"] = 0;
                $response["message"] = "Order detail created successfully";
                $response["odid"] = $order_detail_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = 1;
                $response["message"] = "Failed to create order detail. Please try again";
                echoRespnse(200, $response);
            }  
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

/**
 * Listing all tasks of particual user
 * method GET
 * url /tasks          
 */
$app->get('/tasks', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();
            // fetching all user tasks
            $result = $db->getAllUserTasks($user_id); 
            $response["error"] = false;
            $response["tasks"] = array();
            foreach ($result as $task) {
                $tmp = array();
                $tmp["id"] = $task["id"];
                $tmp["task"] = $task["task"];
                $tmp["status"] = $task["status"];
                $tmp["createdAt"] = $task["created_at"];
                array_push($response["tasks"], $tmp);
            }
            echoRespnse(200, $response);
        });

/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/tasks/:id', 'authenticate', function($task_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getTask($task_id, $user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["task"] = $result["task"];
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /tasks/
 */
$app->post('/tasks', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('task'));

            $response = array();
            $task = $app->request->post('task');

            global $user_id;
            $db = new DbHandler();

            // creating new task
            $task_id = $db->createTask($user_id, $task);

            if ($task_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Task created successfully";
                $response["task_id"] = $task_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create task. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
$app->put('/tasks/:id', 'authenticate', function($task_id) use($app) {
            // check for required params
            verifyRequiredParams(array('task', 'status'));

            global $user_id;            
            $task = $app->request->put('task');
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateTask($user_id, $task_id, $task, $status);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Task updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Task failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
$app->delete('/tasks/:id', 'authenticate', function($task_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $task_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Task deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Task failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = 1;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = 1;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>