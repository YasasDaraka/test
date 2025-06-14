package lk.ijse.gdse66.helloshoes.api;

import jakarta.validation.Valid;
import lk.ijse.gdse66.helloshoes.dto.EmployeeDTO;
import lk.ijse.gdse66.helloshoes.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1/employee")
@CrossOrigin
public class EmployeeController {
    public EmployeeController() {
        System.out.println("EmployeeController");
    }
    @Autowired
    EmployeeService empService;

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/getAll")
    public List<EmployeeDTO> getAllEmployees() {
        return empService.getAllEmployees();
    }

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/search/{id:E00-0*[1-9]\\d{0,2}}")
    public EmployeeDTO getEmployee(@PathVariable("id") String id) {
        return empService.searchEmployee(id);
    }

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(path = "/getGenId")
    public String getEmployeeGenId() {
        return empService.getEmployeeGenId();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<Void> saveEmployee(@Valid @RequestBody EmployeeDTO dto) {
       // System.out.println("Received employee data: " + dto.toString());
        empService.saveEmployee(dto);
        return ResponseEntity.ok().build();
    }

    @PutMapping
    public ResponseEntity<Void> updateEmployee(@Valid @RequestBody EmployeeDTO dto) {
       // System.out.println("Received employee data: " + dto.toString());
        empService.updateEmployee(dto);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping(params = "empId")
    public ResponseEntity<Void> deleteEmployee(@RequestParam("empId") String cusId) {
        empService.deleteEmployee(cusId);
        return ResponseEntity.noContent().build();
    }

}
