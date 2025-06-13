package lk.ijse.gdse66.helloshoes.api;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lk.ijse.gdse66.helloshoes.auth.request.SignInRequest;
import lk.ijse.gdse66.helloshoes.auth.request.SignUpRequest;
import lk.ijse.gdse66.helloshoes.auth.response.JwtAuthResponse;
import lk.ijse.gdse66.helloshoes.dto.UserDTO;
import lk.ijse.gdse66.helloshoes.entity.User;
import lk.ijse.gdse66.helloshoes.service.AuthenticationService;
import lk.ijse.gdse66.helloshoes.service.JwtService;
import lk.ijse.gdse66.helloshoes.service.UserService;
import lk.ijse.gdse66.helloshoes.service.util.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin
public class UserController {

    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final JwtService jwtService;

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthResponse> signIn(
            @RequestBody SignInRequest signInRequest){

        Map<String, String> sign = authenticationService.signIn(signInRequest);
        String refreshToken = sign.get("refreshToken");
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .build();

        return ResponseEntity.ok()
                .header("Set-Cookie", cookie.toString())
                .body(new JwtAuthResponse(sign.get("token")));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthResponse> refreshToken(HttpServletRequest request) {
        // Extract refresh token from cookie
        Cookie[] cookies = request.getCookies();
        String refreshToken = Arrays.stream(cookies)
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (refreshToken == null || !jwtService.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(JwtAuthResponse.builder().build());
        }

        Claims claims = jwtService.getClaimsFromToken(refreshToken);
        String email = claims.get("email", String.class);
        String role = claims.get("role", String.class);
        User user = new User();
        user.setEmail(email);
        Role role1 = null;
        if ("ADMIN".equals(role)){
            role1=Role.ADMIN;

        }else if("USER".equals(role)){
            role1=Role.USER;
        }
        user.setRole(role1);

        String newAccessToken = jwtService.generateToken(user);

        return ResponseEntity.ok(new JwtAuthResponse(newAccessToken));
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthResponse> signUp(
            @RequestBody SignUpRequest signUpRequest){
        System.out.println(signUpRequest);
        return ResponseEntity.ok(
                authenticationService.signUp(signUpRequest));
    }
    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/search/{id}")
    public UserDTO getUser(@PathVariable("id") String id) {
        return userService.searchUser(id);
    }
    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/getall/{id}")
    public ResponseEntity<List<UserDTO>> getAllUser(@PathVariable("id") String id) {
        if ("user".equals(id)) {
            List<UserDTO> users = userService.findAllByRole("USER");
            return ResponseEntity.ok(users);
        } else if ("admin".equals(id)) {
            List<UserDTO> admins = userService.findAllByRole("ADMIN");
            return ResponseEntity.ok(admins);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @ResponseStatus(HttpStatus.OK)
    @PostMapping(path = "/pass")
    public ResponseEntity<Boolean> checkPassword(@RequestBody UserDTO dto) {
        System.out.println(dto.toString());
        boolean isCorrect = userService.checkPassword(dto);
        return ResponseEntity.ok(isCorrect);
    }
    @ResponseStatus(HttpStatus.OK)
    @DeleteMapping(path = "/admin")
    public ResponseEntity<Void> deleteAdmin(@Valid @RequestBody UserDTO dto) {
            userService.deleteUser(dto, Role.ADMIN);
        return ResponseEntity.noContent().build();
    }
    @ResponseStatus(HttpStatus.OK)
    @DeleteMapping(path = "/user")
    public ResponseEntity<Void> deleteUser(@Valid @RequestBody UserDTO dto) {
        userService.deleteUser(dto,Role.USER);
        return ResponseEntity.noContent().build();
    }
    @PutMapping(path = "/admin")
    public ResponseEntity<Void> updateAdmin(@Valid @RequestBody UserDTO dto) {
        System.out.println("Received user data: " + dto.toString());
        userService.updateUser(dto,"ADMIN");
        return ResponseEntity.noContent().build();
    }
    @PutMapping(path = "/user")
    public ResponseEntity<Void> updateUser(@Valid @RequestBody UserDTO dto) {
        System.out.println("Received user data: " + dto.toString());
        userService.updateUser(dto,"USER");
        return ResponseEntity.noContent().build();
    }
}
