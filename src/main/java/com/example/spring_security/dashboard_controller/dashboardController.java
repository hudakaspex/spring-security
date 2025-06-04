package com.example.spring_security.dashboard_controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/api/dashboard")
public class dashboardController {

    @GetMapping()
    @Secured("ADMIN")
    public String getDashboardData() {
        return "Dashboard data is available in several minutes";
    }
    
}
