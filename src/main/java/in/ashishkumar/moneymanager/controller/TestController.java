package in.ashishkumar.moneymanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1.0/test")
@Slf4j
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        log.info("Test public GET endpoint called");
        return "Public GET endpoint works!";
    }

    @PostMapping("/public")
    public String publicPost(@RequestBody String body) {
        log.info("Test public POST endpoint called with body: {}", body);
        return "Public POST works! Body: " + body;
    }
}