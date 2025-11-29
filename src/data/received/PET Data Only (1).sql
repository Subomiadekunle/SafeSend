/*****   PET_OWNER DATA  **********/

INSERT INTO PET_OWNER VALUES(1, 'Downs', 'Marsha', '555-537-8765', 'Marsha.Downs@somewhere.com');
INSERT INTO PET_OWNER VALUES(2, 'James', 'Richard', '555-537-7654', 'Richard.James@somewhere.com');
INSERT INTO PET_OWNER VALUES(3, 'Frier', 'Liz', '555-537-6543', 'Liz.Frier@somewhere.com');
INSERT INTO PET_OWNER VALUES(4,'Trent', 'Miles','314-977-1234','sluanimallover@slu.edu');

/*****   BREED DATA  *****/

INSERT INTO BREED VALUES('BorderCollie', 15.0, 22.5, 20);
INSERT INTO BREED VALUES('Cashmier', 10.0, 15.0, 12);
INSERT INTO BREED VALUES('Collie Mix', 17.5, 25.0, 18);
INSERT INTO BREED VALUES('Std. Poodle', 22.5, 30.0, 18);
INSERT INTO BREED (breedname) VALUES('Unknown');

/*****   PET DATA  *****/

INSERT INTO PET VALUES (1, 'King', 'Dog', 'Std. Poodle', '27-Feb-19', 25.5, 1);
INSERT INTO PET VALUES (2, 'Teddy', 'Cat', 'Cashmier', '01-Feb-20', 10.5, 2);
INSERT INTO PET VALUES (3, 'Fido', 'Dog', 'Std. Poodle', '17-Jul-18', 28.5, 1);
INSERT INTO PET VALUES (4, 'AJ', 'Dog', 'Collie Mix', '05-May-19', 20.0, 3);
INSERT INTO PET VALUES (5, 'Cedro', 'Cat', 'Unknown', '06-Jun-17', 9.5, 2);
INSERT INTO PET VALUES (6, 'Woolley', 'Cat', 'Unknown', '06-May-17', 11, 2);
INSERT INTO PET VALUES (7, 'Buster', 'Dog', 'BorderCollie', '11-Dec-16', 25.0, 4);
