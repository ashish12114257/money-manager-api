package in.ashishkumar.moneymanager.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Public endpoint works!";
    }

    @PostMapping("/public")
    public String publicPost(@RequestBody String body) {
        return "Public POST works! Body: " + body;
    }
}