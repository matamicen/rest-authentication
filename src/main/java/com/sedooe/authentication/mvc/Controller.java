package com.sedooe.authentication.mvc;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class Controller {


    @RequestMapping(value = "/resource", method = RequestMethod.GET)
    public Map<String, String> getResource(HttpServletRequest req, @RequestParam(value = "param1") String param1, @AuthenticationPrincipal User authenticatedUser) {
        Map<String, String> resource = new HashMap<String, String>();
        try {

          resource.put("resource", "here is some resource");

          if (!req.getSession().isNew())
          {     resource.put("resource2", "Variable Sesion anterior: " + req.getSession().getAttribute("name").toString());

          }
          req.getSession().setAttribute("name", param1);
          resource.put("resource3", "Variable de sesion recien ingresada por el usuario: " + req.getSession().getAttribute("name").toString());

            if (authenticatedUser != null) {
                resource.put("resource4", "username:" + authenticatedUser.getUsername().toString() + " authorithies:" + authenticatedUser.getAuthorities().toString() + "x-auth-token" +  req.getSession().getId());

            }
         // System.out.println("Variable de sesion ingresada por el usuario: " + session.getAttribute("name"));
      } catch (Exception e)
      {e.printStackTrace();

      }

        return resource;
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpSession session) {
        session.invalidate();
    }
}
