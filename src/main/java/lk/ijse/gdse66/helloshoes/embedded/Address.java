package lk.ijse.gdse66.helloshoes.embedded;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Embeddable
public class Address {

    private String buildNo;

    private String lane;

    private String city;

    private String state;

    private String postalCode;

}