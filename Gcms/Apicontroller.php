<?php
/**
 * @filesource Gcms/Apicontroller.php
 *
 * @copyright 2016 Goragod.com
 * @license http://www.kotchasan.com/license/
 *
 * @see http://www.kotchasan.com/
 */

namespace Gcms;

use Kotchasan\Http\Request;

/**
 * API Controller base class
 *
 * @author Goragod Wiriya <admin@goragod.com>
 *
 * @since 1.0
 */
class Apicontroller extends \Kotchasan\KBase
{
    /**
     * แม่แบบคอนโทรลเลอร์ สำหรับ API
     *
     * @param Request $request
     *
     * @return JSON
     */
    public function index(Request $request)
    {
        if (empty(self::$cfg->api_token) || empty(self::$cfg->api_ips)) {
            // ยังไม่ได้สร้าง Token หรือ ยังไม่ได้อนุญาต IP
            $result = array(
                'code' => 503,
                'message' => 'Unavailable API',
            );
        } elseif (in_array('0.0.0.0', self::$cfg->api_ips) || in_array($request->getClientIp(), self::$cfg->api_ips)) {
            // ตรวจสอบ token
            $validate = $this->validateToken($request);
            if ($validate === '') {
                // รับค่าที่ส่งมาจาก Router
                $module = $request->get('module')->filter('a-z0-9');
                $method = $request->get('method')->filter('a-z');
                $action = $request->get('action')->filter('a-z');
                // แปลงเป็นชื่อคลาส สำหรับ Model เช่น
                // api.php/v1/user/create ได้เป็น V1\User\Model::create
                $className = ucfirst($module).'\\'.ucfirst($method).'\\Model';
                // ตรวจสอบ method
                if (method_exists($className, $action)) {
                    // เรียกใช้งาน Class
                    $result = createClass($className)->$action($request);
                } else {
                    // error ไม่พบ class หรือ method
                    $result = array(
                        'code' => 404,
                        'message' => 'Object Not Found',
                    );
                }
            } else {
                // Token ไม่ถูกต้อง
                $result = array(
                    'code' => 401,
                    'message' => $validate,
                );
            }
        } else {
            // ไม่อนุญาต IP
            $result = array(
                'code' => 403,
                'message' => 'Forbidden',
            );
        }
        // Response คืนค่ากลับเป็น JSON ตาม $result
        $response = new \Kotchasan\Http\Response();
        $response->withHeaders(array(
            'Content-type' => 'application/json; charset=UTF-8',
        ))
            ->withStatus(empty($result['code']) ? 200 : $result['code'])
            ->withContent(json_encode($result))
            ->send();
    }

    /**
     * ตรวจสอบ TOKEN
     * คืนค่าข้อความว่างถ้าสำเร็จ
     * ไม่สำเร็จคืนค่าข้อผิดพลาด
     *
     * @param Request $request
     *
     * @return string
     */
    private function validateToken(Request $request)
    {
        // ตรวจสอบ token
        if (self::$cfg->api_token !== $request->post('token')->toString()) {
            return 'Invalid token';
        } else {
            // ค่าที่ส่งมา
            $params = $request->getParsedBody();
            if (count($params) > 1) {
                if (!isset($params['sign'])) {
                    // ไม่ได้ระบุ sign มา
                    return 'Invalid sign';
                } else {
                    // ตรวจสอบ sign
                    $sign = $params['sign'];
                    unset($params['sign']);
                    return $sign === \Kotchasan\Password::generateSign($params, self::$cfg->api_secret) ? '' : 'Invalid sign';
                }
            } else {
                return '';
            }
        }
    }
}
