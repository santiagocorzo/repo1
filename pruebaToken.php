<?php

namespace AppBundle\Controller\AppPrivate\Api;

use AppBundle\Controller\AppController;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpFoundation\JsonResponse;
use AppBundle\Entity\Incidende;
use AppBundle\Entity\Project;
use AppBundle\Entity\AppUser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\ValidationData;

class ApiController extends AppController
{
    /**
     * @Route("/getToken")
     * @Method("POST")
     */
    public function getTokenAction(Request $request)
    {   
        
        $username = $request->get('username');
        $em = $this->getDoctrine()->getManager();
        $query = $em->createQuery("SELECT u FROM AppBundle\Entity\AppUser u WHERE u.username = :username")
                    ->setParameter('username',$username);
        
        $user = $query->getArrayResult();
        
        if($user){
            $authenticationUtils = $this->get("security.authentication_utils");
            $error = $authenticationUtils->getLastAuthenticationError();
            $token = (new Builder())->setIssuer('http://localhost:8000')
                        ->setAudience('http://localhost:8000')
                        ->setId('4f1g23a12aa',true)
                        ->setIssuedAt(time())
                        ->setExpiration(time()+3600)
                        ->set('uid',$user[0]['id'])
                        ->sign(new Sha256(),"S4NTI46O")
                        ->getToken();
            $tokenValue = $token->__toString();
            $data = array(
                'token' => $tokenValue,
                'userData' => $user,
                'error' => $error
            ); 
            return new JsonResponse($data);
        }
        return new Response("Error");
    }
    /**
     * @Route("/api/auth/{apikey}", name="api_login")
     * 
     * @Method("POST")
     */
    public function loginApiAction(Request $request, $apikey)
    {
        if($authenticationUtils = $this->get("security.authentication_utils")){
            return new Response("Bienvenido");
        }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return new  Response($error);
    }
    /**
       * @Route("/api/test/{apikey}")
       * @Security("has_role('ROLE_API')")
       */
    public function testAction($apikey)
    {
        $appUser = $this->getUser();
        $userId = $appUser->getId();
        $em = $this->getDoctrine()->getManager();
        $incidencias = $em->getRepository('AppBundle:AppUser')->firstResponsibleIncidence();
        $respuesta = array('Incidencias'=>$incidencias);
        $response = new Response();
        $response->setCharset('ISO-8859-1');
        $response->headers->set('Content-Type', 'application/json');          
        $response->setContent(json_encode($respuesta, JSON_UNESCAPED_UNICODE));
        return $response;
    }

    /**
     * @Route("/api/test/2/{apikey}")
     * @Security("has_role('ROLE_API')")
     */
    public function testT($apikey)
    {
        $appUser = $this->getUser();
        $userId = $appUser->getId();
        $em = $this->getDoctrine()->getManager();
        $usuarioWhitToken = $em->getRepository('AppBundle:AppUser')->find($userId);
        $response = new Response();
        $response->setCharset('ISO-8859-1');
        $response->headers->set('Content-Type', 'application/json');          
        $response->setContent(json_encode(array('user'=>$usuarioWhitToken), JSON_UNESCAPED_UNICODE));
        return $response;

    }



}
