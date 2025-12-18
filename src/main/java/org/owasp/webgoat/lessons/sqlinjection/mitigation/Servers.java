/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

    private final LessonDataSource dataSource;

    @AllArgsConstructor
    @Getter
    private class Server {

        private String id;
        private String hostname;
        private String ip;
        private String mac;
        private String status;
        private String description;
    }

    public Servers(LessonDataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public List<Server> sort(@RequestParam String column) throws Exception {
        List<Server> servers = new ArrayList<>();

        // Whitelist of allowed sort columns
        Map<String, String> ALLOWED_COLUMNS = Map.of(
            "id", "id",
            "hostname", "hostname",
            "ip", "ip",
            "mac", "mac",
            "status", "status",
            "description", "description"
        );

        // Use a safe default if the requested column is not allowed
        String orderBy = ALLOWED_COLUMNS.getOrDefault(column, "id");

        String sql =
            "SELECT id, hostname, ip, mac, status, description " +
            "FROM SERVERS " +
            "WHERE status <> 'out of order' " +
            "ORDER BY " + orderBy;

        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement(sql);
             var rs = statement.executeQuery()) {

            while (rs.next()) {
                Server server =
                    new Server(
                        rs.getString(1),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getString(4),
                        rs.getString(5),
                        rs.getString(6));
                servers.add(server);
            }
        }

        return servers;
    }
}
