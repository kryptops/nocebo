package server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class listener {
    @GetMapping("/60000")
    public Mono<String> authEndpoint()
    {
        
    }

    @GetMapping("/60001")
    public Mono<String> dataEndpoint()
    {

    }

}
