package com.sales.management.Service.impl;

import com.sales.management.BaseResponse.APIResponse;
import com.sales.management.DTO.RoleDTO;
import com.sales.management.DTO.UserDTO;
import com.sales.management.DTO.UserRoleDTO;
import com.sales.management.ExceptionHandling.CustomException;
import com.sales.management.Model.Role;
import com.sales.management.Model.User;
import com.sales.management.Model.UserRole;
import com.sales.management.Repository.RoleRepository;
import com.sales.management.Repository.UserRepository;
import com.sales.management.Repository.UserRoleRepository;
import com.sales.management.Service.UserInterface;
import com.sales.management.Util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
@Transactional
public class UserServiceImpl implements UserInterface {


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public User Saveuser(UserDTO userDTO) {
        User user = new User();
        user.setName(userDTO.getName());
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        user.setPassword(bcrypt.encode(userDTO.getPassword()));
        userRepository.save(user);
        saveRole(userDTO.getRoles(), user);
        return user;
    }
    private void saveRole(List<RoleDTO> roles, User userDetail) {
        try {
            List<UserRole> userRoles = new LinkedList<>();
            if (Objects.nonNull(roles) && roles.size() > 0) {
                roles.stream().forEachOrdered(role -> {
                    Role role1 = roleRepository.findById(role.getId())
                            .orElseThrow(() -> new RuntimeException("not found"));
                    UserRole userRole = new UserRole();
                    userRole.setUser(userDetail);
                    userRole.setRole(role1);
                    userRoles.add(userRole);
                });
                userRoleRepository.saveAll(userRoles);
            }
        } catch (NoSuchElementException e) {
                throw new CustomException("400","Bad Request");
        }
    }

    @Override
    public UserRoleDTO logOfUser(UserRoleDTO userRoleDTO) {
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        List<Role> roles = new LinkedList<>();
        try {
            Optional<User> user = userRepository.findByName(userRoleDTO.getUserName());
            boolean status = bcrypt.matches(userRoleDTO.getPassword(), user.get().getPassword());
            if (user.isPresent() && status == true) {
                List<UserRole> userRoles = userRoleRepository.findByUserId(user.get().getId());
                userRoles.stream().forEachOrdered(userRole -> {
                    Role role = userRole.getRole();
                    roles.add(role);
                });
                String Token = JwtUtil.generateToken("secret", user.get().getId(), "user", user.get().getName(), roles);
                userRoleDTO.setUserName(user.get().getName());
                userRoleDTO.setId(user.get().getId());
                userRoleDTO.setRoleList(user.get().getRoles());
                userRoleDTO.setJwtToken(Token);
            }
        }  catch (NoSuchElementException e) {
            throw new CustomException("401","Unauthorised");
        }
        return userRoleDTO;
    }

    @Override
    public APIResponse<User> pageOfUser(int offset, int pageSize, String name) {
        APIResponse apiResponse = new APIResponse();
        try {
            Pageable paging = PageRequest.of(offset, pageSize);
            Page<User> Users = userRepository.searchAllByNameLike("%" + name + "%", paging);
            apiResponse.setResponse(Users);
            apiResponse.setRecordCount(Users.getTotalPages());
        } catch (NoSuchElementException e) {
            throw new CustomException("400","Bad Request");
        }
     return apiResponse;
    }


    public UserDetails loadByuserName(String username) throws UsernameNotFoundException {
        Optional<User> userDetail = userRepository.findByName(username);
        List<Role> roles = new LinkedList<>();
        if (userDetail == null) {
            throw new CustomException("404","Not Found");
        }
        else{
            List<UserRole> userRoles = userRoleRepository.findByUserId(userDetail.get().getId());
            userRoles.stream().forEachOrdered(userRole -> {
                Role role = userRole.getRole();
                roles.add(role);
            });
            return new org.springframework.security.core.userdetails.User(userDetail.get().getName(), userDetail.get().getPassword(), getAuthority(roles));
        }
    }

    private List getAuthority(List<Role> role){
        List authorities=new ArrayList();
        role.stream().forEachOrdered(roleget -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" +roleget.getRoleName()));
        });
        return authorities;
    }



    @Override
    public Optional<User> updateUser(UserDTO userDTO) {
        Optional<User> existUser = userRepository.findById(userDTO.getId());
        if (existUser.isPresent()) {
            existUser.get().setName(userDTO.getName());
            BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
            existUser.get().setPassword(bcrypt.encode(userDTO.getPassword()));
            userRepository.save(existUser.get());
        } else {
            throw new CustomException("404","Not Found");
        }

        return existUser;
    }


    @Override
    public Optional<User> FindByUserId(int id) {
        Optional<User> users = userRepository.findById(id);
        return users;
    }


    @Override
    public User deletebyid(int id) {
        User user = new User();
        userRepository.deleteById(id);
        return user;
    }



}
